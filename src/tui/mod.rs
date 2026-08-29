//! Interactive interface (TUI): terminal, event loop, keys and drawing.

mod app;
mod clipboard;
mod export;
mod probe;
mod theme;

use crate::cli::{Cli, Scope};
use anyhow::Result;
use app::{App, FormFocus, Pane, RangeKind, RangeRow};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use std::time::Duration;

pub fn run_tui(cli: &Cli) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!("the TUI needs an interactive terminal (stdin/stdout must be a tty)");
    }
    // Check permission before going full screen, so the hint stays readable.
    if let Err(e) = crate::scan::preflight_permission() {
        let msg = format!("{:#}", e);
        if msg.contains("CAP_NET_RAW") {
            anyhow::bail!("{}", msg);
        }
    }

    let mut app = App::new()?;
    apply_cli(&mut app, cli);

    let mut terminal = ratatui::init();
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();

    // If the capability was missing, print the instructions once restored.
    if let Some(msg) = &app.perm_error {
        eprintln!("{}", msg);
    }
    res
}

/// Applies command line flags as the form's initial state.
fn apply_cli(app: &mut App, cli: &Cli) {
    if let Some(name) = &cli.iface {
        if let Some(i) = app.ifaces.iter().position(|x| &x.name == name) {
            app.iface_idx = i;
        }
    }
    app.scope = cli.scope;
    app.adv.rate = cli.rate;
    app.adv.settle = cli.settle;
    app.adv.passes = cli.passes;
    app.adv.no_ipv6 = cli.no_ipv6;
    app.adv.spa = cli.spa.clone();
    // We do not inherit passive_secs from the CLI (15s default): the TUI is
    // on-demand and listens for zero seconds by default. Adjust it in the
    // Advanced drawer.
    if let Some(l) = &cli.leases_file {
        app.adv.leases_file = l.clone();
    }
    // Explicit ranges from the CLI replace the pre-filled row.
    let mut rows: Vec<RangeRow> = Vec::new();
    for e in &cli.expected {
        rows.push(RangeRow::new(e.clone(), RangeKind::Expected));
    }
    for x in &cli.excluded {
        rows.push(RangeRow::new(x.clone(), RangeKind::Ignored));
    }
    // --range means "sweep this too", not "this is legitimate" — as in the CLI.
    for r in &cli.ranges {
        rows.push(RangeRow::new(r.clone(), RangeKind::Target));
    }
    if !rows.is_empty() {
        app.ranges = rows;
    }
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| render(f, app))?;

        // While the scan runs (or has just finished), recompute the findings.
        if app.scan.is_some() && app.last_refresh.elapsed() > Duration::from_millis(250) {
            app.refresh_findings();
        }
        app.tick_toast();

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    handle_key(app, k);
                }
            }
        }
        if app.should_quit {
            app.cancel_scan();
            break;
        }
    }
    Ok(())
}

// =====================================================================
// Keys
// =====================================================================

fn handle_key(app: &mut App, k: event::KeyEvent) {
    // Ctrl-C always quits.
    if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    // Overlays swallow everything first.
    if app.perm_error.is_some() {
        app.should_quit = true;
        return;
    }
    if app.help_open {
        app.help_open = false;
        return;
    }

    // Text field editing mode.
    if let Some(buf) = app.editing.as_mut() {
        match k.code {
            KeyCode::Enter => commit_edit(app),
            KeyCode::Esc => app.editing = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        return;
    }

    // Filter typing mode.
    if app.filtering {
        match k.code {
            KeyCode::Enter | KeyCode::Esc => app.filtering = false,
            KeyCode::Backspace => {
                if let Some(s) = app.filter.as_mut() {
                    s.pop();
                    if s.is_empty() {
                        app.filter = None;
                        app.filtering = false;
                    }
                }
            }
            KeyCode::Char(c) => {
                app.filter.get_or_insert_with(String::new).push(c);
            }
            _ => {}
        }
        return;
    }

    match k.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Char('r') => app.start_scan(),
        KeyCode::Tab => {
            app.pane = match app.pane {
                Pane::Form => Pane::Results,
                Pane::Results => Pane::Form,
            }
        }
        KeyCode::Esc => {
            if app.is_running() {
                app.cancel_scan();
            }
        }
        _ => match app.pane {
            Pane::Form => handle_form_key(app, k),
            Pane::Results => handle_results_key(app, k),
        },
    }
}

fn form_items(app: &App) -> Vec<FormFocus> {
    let mut v = vec![FormFocus::Interface, FormFocus::Scope];
    for i in 0..app.ranges.len() {
        v.push(FormFocus::Range(i));
    }
    v.push(FormFocus::AdvancedToggle);
    if app.advanced_open {
        v.extend([
            FormFocus::AdvSpa,
            FormFocus::AdvRate,
            FormFocus::AdvSettle,
            FormFocus::AdvPasses,
            FormFocus::AdvNoIpv6,
            FormFocus::AdvLeases,
            FormFocus::AdvPassive,
        ]);
    }
    v
}

fn handle_form_key(app: &mut App, k: event::KeyEvent) {
    // The form is locked while a scan runs.
    if app.is_running() {
        return;
    }
    let items = form_items(app);
    let cur = items.iter().position(|f| *f == app.form_focus).unwrap_or(0);

    match k.code {
        KeyCode::Down | KeyCode::Char('j') => {
            let n = (cur + 1).min(items.len().saturating_sub(1));
            app.form_focus = items[n];
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let n = cur.saturating_sub(1);
            app.form_focus = items[n];
        }
        KeyCode::Char('a') => {
            // Add a range after the current one and start editing it.
            let at = match app.form_focus {
                FormFocus::Range(i) => i + 1,
                _ => app.ranges.len(),
            };
            app.ranges.insert(at, RangeRow::new("", RangeKind::Expected));
            app.form_focus = FormFocus::Range(at);
            app.editing = Some(String::new());
        }
        KeyCode::Char('d') => {
            if let FormFocus::Range(i) = app.form_focus {
                app.ranges.remove(i);
                app.form_focus = match app.ranges.len() {
                    0 => FormFocus::Scope,
                    n => FormFocus::Range(i.min(n - 1)),
                };
            }
        }
        // Sweep only the focused range, now: the hypothesis loop.
        KeyCode::Char('s') => {
            if let FormFocus::Range(i) = app.form_focus {
                app.scan_single(i);
            } else {
                app.toast("put the cursor on a range to sweep just that one");
            }
        }
        KeyCode::Char(' ') => toggle_focused(app),
        KeyCode::Enter => activate_focused(app),
        KeyCode::Left | KeyCode::Char('h') => cycle_focused(app, false),
        KeyCode::Right | KeyCode::Char('l') => cycle_focused(app, true),
        _ => {}
    }
}

/// Space: cycles a range's role, or toggles an advanced boolean.
fn toggle_focused(app: &mut App) {
    match app.form_focus {
        FormFocus::Range(i) => {
            if let Some(r) = app.ranges.get_mut(i) {
                r.kind = r.kind.next();
            }
        }
        FormFocus::AdvNoIpv6 => app.adv.no_ipv6 = !app.adv.no_ipv6,
        FormFocus::AdvancedToggle => app.advanced_open = !app.advanced_open,
        _ => {}
    }
}

/// Enter: activates the focused field (edit text, cycle, open the drawer).
fn activate_focused(app: &mut App) {
    match app.form_focus {
        FormFocus::Interface => cycle_focused(app, true),
        FormFocus::Scope => cycle_focused(app, true),
        FormFocus::AdvancedToggle => app.advanced_open = !app.advanced_open,
        FormFocus::AdvNoIpv6 => app.adv.no_ipv6 = !app.adv.no_ipv6,
        FormFocus::Range(i) => {
            app.editing = Some(app.ranges.get(i).map(|r| r.text.clone()).unwrap_or_default());
        }
        FormFocus::AdvSpa => app.editing = Some(app.adv.spa.clone()),
        FormFocus::AdvRate => app.editing = Some(app.adv.rate.to_string()),
        FormFocus::AdvSettle => app.editing = Some(app.adv.settle.to_string()),
        FormFocus::AdvPasses => app.editing = Some(app.adv.passes.to_string()),
        FormFocus::AdvLeases => app.editing = Some(app.adv.leases_file.clone()),
        FormFocus::AdvPassive => app.editing = Some(app.adv.passive_secs.to_string()),
    }
}

/// Left/right: cycles the values of enumerated fields.
fn cycle_focused(app: &mut App, forward: bool) {
    match app.form_focus {
        FormFocus::Interface => {
            let n = app.ifaces.len().max(1);
            app.iface_idx = if forward {
                (app.iface_idx + 1) % n
            } else {
                (app.iface_idx + n - 1) % n
            };
            // On an interface change, re-suggest the local subnet in row one.
            if let Some(net) = app.ifaces.get(app.iface_idx).and_then(|i| i.net) {
                match app.ranges.len() {
                    0 => app.ranges.push(RangeRow::new(net.to_string(), RangeKind::Expected)),
                    1 => app.ranges[0] = RangeRow::new(net.to_string(), RangeKind::Expected),
                    _ => {}
                }
            }
        }
        FormFocus::Scope => {
            let order = [Scope::Auto, Scope::Rfc1918, Scope::Private16, Scope::None];
            let cur = order.iter().position(|s| *s == app.scope).unwrap_or(0);
            let n = order.len();
            app.scope = if forward { order[(cur + 1) % n] } else { order[(cur + n - 1) % n] };
        }
        FormFocus::Range(i) => {
            if let Some(r) = app.ranges.get_mut(i) {
                r.kind = if forward { r.kind.next() } else { r.kind.prev() };
            }
        }
        FormFocus::AdvSpa => {
            let order = ["probe", "local", "dest", "neighbor"];
            let cur = order.iter().position(|s| *s == app.adv.spa).unwrap_or(0);
            let n = order.len();
            app.adv.spa =
                if forward { order[(cur + 1) % n] } else { order[(cur + n - 1) % n] }.to_string();
        }
        _ => {}
    }
}

fn commit_edit(app: &mut App) {
    let buf = match app.editing.take() {
        Some(b) => b,
        None => return,
    };
    match app.form_focus {
        FormFocus::Range(i) => {
            if let Some(r) = app.ranges.get_mut(i) {
                r.text = buf;
            }
        }
        FormFocus::AdvSpa => app.adv.spa = buf,
        FormFocus::AdvRate => app.adv.rate = buf.trim().parse().unwrap_or(app.adv.rate),
        FormFocus::AdvSettle => app.adv.settle = buf.trim().parse().unwrap_or(app.adv.settle),
        FormFocus::AdvPasses => app.adv.passes = buf.trim().parse().unwrap_or(app.adv.passes),
        FormFocus::AdvLeases => app.adv.leases_file = buf,
        FormFocus::AdvPassive => {
            app.adv.passive_secs = buf.trim().parse().unwrap_or(app.adv.passive_secs)
        }
        _ => {}
    }
}

fn handle_results_key(app: &mut App, k: event::KeyEvent) {
    match k.code {
        KeyCode::Enter => app.start_scan(),
        KeyCode::Down | KeyCode::Char('j') => {
            let n = app.visible_indices().len();
            if n > 0 {
                app.result_idx = (app.result_idx + 1).min(n - 1);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.result_idx = app.result_idx.saturating_sub(1);
        }
        KeyCode::Char('/') => {
            app.filtering = true;
            app.filter.get_or_insert_with(String::new);
        }
        KeyCode::Char('f') => {
            app.only_flagged = !app.only_flagged;
            app.result_idx = 0;
        }
        KeyCode::Char('w') => app.whitelist_selected(),
        KeyCode::Char('y') => app.copy_mac_selected(),
        KeyCode::Char('p') => app.probe_selected(),
        KeyCode::Char('e') => app.export(),
        _ => {}
    }
}

// =====================================================================
// Drawing
// =====================================================================

fn render(f: &mut Frame, app: &App) {
    let root = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(f.area());
    let cols = Layout::horizontal([Constraint::Length(36), Constraint::Min(0)]).split(root[0]);

    render_form(f, app, cols[0]);
    render_results(f, app, cols[1]);
    render_status(f, app, root[1]);

    if app.help_open {
        render_help(f, f.area());
    }
    if let Some(msg) = &app.perm_error {
        render_perm(f, f.area(), msg);
    }
}

fn focus_marker(app: &App, is: FormFocus) -> Span<'static> {
    if app.pane == Pane::Form && app.form_focus == is {
        Span::styled("› ", theme::accent())
    } else {
        Span::raw("  ")
    }
}

fn render_form(f: &mut Frame, app: &App, area: Rect) {
    let border = if app.pane == Pane::Form { theme::accent() } else { theme::dim() };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(" configuration ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    // Interface row
    let ifname = app.iface_name().unwrap_or_else(|| "—".into());
    lines.push(Line::from(vec![
        focus_marker(app, FormFocus::Interface),
        Span::styled("Interface: ", theme::dim()),
        Span::raw(ifname),
    ]));
    // Scope row
    lines.push(Line::from(vec![
        focus_marker(app, FormFocus::Scope),
        Span::styled("Scope:     ", theme::dim()),
        Span::raw(scope_label(app.scope)),
    ]));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("  Ranges (s sweeps the focused):", theme::dim())));
    lines.push(Line::from(Span::styled(
        "  [ ]network [>]target [!]ignore",
        theme::dim(),
    )));

    for (i, r) in app.ranges.iter().enumerate() {
        let editing = app.editing.is_some() && app.form_focus == FormFocus::Range(i);
        let text = if editing {
            format!("{}_", app.editing.as_deref().unwrap_or(""))
        } else {
            r.text.clone()
        };
        let mut style = Style::default();
        if !r.valid() {
            style = theme::severity_style(crate::correlate::Severity::Critical);
        } else if r.kind == RangeKind::Target {
            style = theme::accent();
        } else if r.kind == RangeKind::Ignored {
            style = theme::dim();
        }
        lines.push(Line::from(vec![
            focus_marker(app, FormFocus::Range(i)),
            Span::styled(format!("[{}] ", r.kind.marker()), theme::accent()),
            Span::styled(if text.is_empty() { "<empty>".into() } else { text }, style),
        ]));
    }

    lines.push(Line::raw(""));
    let adv_arrow = if app.advanced_open { "▾" } else { "▸" };
    lines.push(Line::from(vec![
        focus_marker(app, FormFocus::AdvancedToggle),
        Span::styled(format!("{} Advanced", adv_arrow), theme::dim()),
    ]));
    if app.advanced_open {
        adv_line(app, &mut lines, FormFocus::AdvSpa, "spa", &app.adv.spa);
        adv_line(app, &mut lines, FormFocus::AdvRate, "rate", &app.adv.rate.to_string());
        adv_line(app, &mut lines, FormFocus::AdvSettle, "settle", &app.adv.settle.to_string());
        adv_line(app, &mut lines, FormFocus::AdvPasses, "passes", &app.adv.passes.to_string());
        adv_line(
            app,
            &mut lines,
            FormFocus::AdvNoIpv6,
            "no-ipv6",
            if app.adv.no_ipv6 { "yes" } else { "no" },
        );
        let lf = if app.adv.leases_file.is_empty() { "—" } else { &app.adv.leases_file };
        adv_line(app, &mut lines, FormFocus::AdvLeases, "leases", lf);
        adv_line(
            app,
            &mut lines,
            FormFocus::AdvPassive,
            "passive-s",
            &app.adv.passive_secs.to_string(),
        );
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn adv_line(app: &App, lines: &mut Vec<Line>, focus: FormFocus, name: &str, value: &str) {
    let editing = app.editing.is_some() && app.form_focus == focus;
    let val = if editing {
        format!("{}_", app.editing.as_deref().unwrap_or(""))
    } else {
        value.to_string()
    };
    lines.push(Line::from(vec![
        focus_marker(app, focus),
        Span::styled(format!("  {:<9} ", name), theme::dim()),
        Span::raw(val),
    ]));
}

fn render_results(f: &mut Frame, app: &App, area: Rect) {
    let split = Layout::vertical([Constraint::Min(0), Constraint::Length(6)]).split(area);
    render_table(f, app, split[0]);
    render_detail(f, app, split[1]);
}

fn render_table(f: &mut Frame, app: &App, area: Rect) {
    let border = if app.pane == Pane::Results { theme::accent() } else { theme::dim() };
    let title = format!(
        " hosts ({}{}) ",
        app.visible_indices().len(),
        if app.only_flagged { ", flagged only" } else { ", all" }
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let vis = app.visible_indices();
    let mut lines: Vec<Line> = Vec::new();
    // Header
    lines.push(Line::from(Span::styled(
        format!("{:<3}{:<19}{:<17}{:<24}{}", "", "MAC", "IPv4", "VENDOR", "FLAGS"),
        Style::default().add_modifier(Modifier::BOLD),
    )));

    let height = inner.height.saturating_sub(1) as usize;
    let start = app.result_idx.saturating_sub(height.saturating_sub(1));
    for (row, &fi) in vis.iter().enumerate().skip(start).take(height) {
        let x = &app.findings[fi];
        let sel = row == app.result_idx;
        let glyph = theme::severity_glyph(x.severity);
        let ip = x.ipv4.first().cloned().unwrap_or_else(|| "—".into());
        let vendor = x.vendor.clone().unwrap_or_else(|| {
            if x.locally_administered { "(local/VM)".into() } else { "(?)".into() }
        });
        let flags = x.flags.iter().map(|fl| fl.code()).collect::<Vec<_>>().join(" ");
        let base = theme::severity_style(x.severity);
        let content = format!(
            "{:<3}{:<19}{:<17}{:<24}{}",
            glyph,
            trunc(&x.mac, 18),
            trunc(&ip, 16),
            trunc(&vendor, 23),
            flags
        );
        let style = if sel { base.patch(theme::selected()) } else { base };
        lines.push(Line::from(Span::styled(content, style)));
    }

    if vis.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (nothing yet — press r/Enter to sweep)",
            theme::dim(),
        )));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).border_style(theme::dim()).title(" detalhe ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    if let Some(x) = app.selected_finding() {
        let mut head = vec![
            Span::styled(x.mac.clone(), theme::accent()),
            Span::raw("  "),
            Span::raw(x.vendor.clone().unwrap_or_else(|| "(vendor ?)".into())),
        ];
        if let Some(h) = &x.hostname {
            head.push(Span::styled(format!("  «{}»", h), theme::dim()));
        }
        lines.push(Line::from(head));

        let ips = if x.ipv4.is_empty() { "—".into() } else { x.ipv4.join(", ") };
        lines.push(Line::from(vec![
            Span::styled("IPv4: ", theme::dim()),
            Span::raw(ips),
        ]));
        if !x.ipv6.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("IPv6: ", theme::dim()),
                Span::raw(x.ipv6.join(", ")),
            ]));
        }
        if let Some(l) = &x.lease {
            lines.push(Line::from(vec![
                Span::styled("lease: ", theme::dim()),
                Span::raw(l.clone()),
            ]));
        }
        for fl in &x.flags {
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", fl.code()), theme::severity_style(fl.severity())),
                Span::styled(fl.explain(), theme::dim()),
            ]));
        }
        if !x.sources.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("seen via: {}", x.sources.join(", ")),
                theme::dim(),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled("no host selected", theme::dim())));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();

    if app.filtering || app.filter.is_some() {
        spans.push(Span::styled(
            format!(" filter: {}", app.filter.as_deref().unwrap_or("")),
            theme::accent(),
        ));
        spans.push(Span::raw("   "));
    }

    if let Some(h) = &app.scan {
        let phase = h.progress.phase();
        use crate::scan::Phase;
        let txt = match phase {
            Phase::Sweep => {
                let (s, t) = h.progress.sweep_counts();
                format!(" {} {:.0}% ({}/{})", phase.label(), h.progress.fraction() * 100.0, s, t)
            }
            Phase::Done => " done".into(),
            other => format!(" {}...", other.label()),
        };
        let st = if app.is_running() { theme::accent() } else { theme::dim() };
        spans.push(Span::styled(txt, st));
        spans.push(Span::raw("   "));
    }

    if let Some((msg, _)) = &app.toast {
        spans.push(Span::styled(format!("• {}", msg), theme::accent()));
    } else {
        spans.push(Span::styled(
            "r/Enter run · s sweep range · Tab pane · a add · d del · Space mark · w/y/p host · / filter · f flagged · e export · ? help · q quit",
            theme::dim(),
        ));
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let a = centered(area, 62, 22);
    f.render_widget(Clear, a);
    let block = Block::default().borders(Borders::ALL).border_style(theme::accent()).title(" help ");
    let text = vec![
        Line::from(Span::styled("Global", theme::accent())),
        Line::raw("  r / Enter   run the sweep"),
        Line::raw("  Tab         switch focus form <-> results"),
        Line::raw("  Esc         cancel the running sweep"),
        Line::raw("  ? / q       help / quit"),
        Line::from(Span::styled("Form", theme::accent())),
        Line::raw("  j/k ↑/↓     move between fields"),
        Line::raw("  h/l ←/→     cycle interface/scope/spa/range"),
        Line::raw("  Enter       edit or activate the focused field"),
        Line::raw("  a / d       add / remove a range"),
        Line::raw("  Space       cycle [ ] network -> [>] target -> [!] ignore"),
        Line::raw("  s           sweep only the focused range, now"),
        Line::from(Span::styled("Results", theme::accent())),
        Line::raw("  j/k         move between hosts"),
        Line::raw("  / f         filter by text / flagged only"),
        Line::raw("  w y p       whitelist / copy MAC / probe"),
        Line::raw("  e           export JSON+CSV"),
        Line::raw(""),
        Line::from(Span::styled("  (any key closes)", theme::dim())),
    ];
    let inner = block.inner(a);
    f.render_widget(block, a);
    f.render_widget(Paragraph::new(text), inner);
}

fn render_perm(f: &mut Frame, area: Rect, msg: &str) {
    let a = centered(area, 70, 12);
    f.render_widget(Clear, a);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::severity_style(crate::correlate::Severity::Critical))
        .title(" no permission ");
    let inner = block.inner(a);
    f.render_widget(block, a);
    f.render_widget(
        Paragraph::new(msg.to_string()).wrap(Wrap { trim: false }),
        inner,
    );
}

// ---- layout and text helpers ----

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    let x = area.x + (area.width - w) / 2;
    let y = area.y + (area.height - h) / 2;
    Rect { x, y, width: w, height: h }
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn scope_label(s: Scope) -> String {
    match s {
        Scope::None => "ranges only".into(),
        Scope::Auto => "auto".into(),
        Scope::Private16 => "192.168/16".into(),
        Scope::Rfc1918 => "rfc1918".into(),
    }
}
