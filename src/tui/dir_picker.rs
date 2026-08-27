//! Directory picker for the receive wizard: browse into a directory to save
//! the received file in, or create a new folder inline.

use std::path::PathBuf;

use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};

use super::widgets;

pub struct DirPicker {
    cwd: PathBuf,
    entries: Vec<String>,
    list_state: ListState,
    show_hidden: bool,
    /// `Some` while the user is typing a new folder name.
    new_name: Option<String>,
    /// Insertion point in `new_name` (byte offset, always on a char
    /// boundary): standard line editing.
    name_cursor: usize,
    error: Option<String>,
}

/// What a key press did to the picker.
pub enum DirPickerStep {
    Stay,
    Back,
    Choose(PathBuf),
}

impl DirPicker {
    /// Start in the process's current directory.
    pub fn new() -> Result<Self> {
        let cwd = std::env::current_dir().context("Cannot determine the current directory")?;
        Ok(Self::at(cwd))
    }

    /// Start in a specific directory (e.g. returning from a later screen).
    pub fn at(cwd: PathBuf) -> Self {
        let mut picker = Self {
            cwd,
            entries: Vec::new(),
            list_state: ListState::default(),
            show_hidden: false,
            new_name: None,
            name_cursor: 0,
            error: None,
        };
        picker.refresh();
        picker
    }

    fn refresh(&mut self) {
        self.entries.clear();
        self.error = None;
        match std::fs::read_dir(&self.cwd) {
            Ok(read) => {
                for dir_entry in read.flatten() {
                    let Ok(name) = dir_entry.file_name().into_string() else {
                        continue;
                    };
                    if !self.show_hidden && name.starts_with('.') {
                        continue;
                    }
                    if dir_entry.path().is_dir() {
                        self.entries.push(name);
                    }
                }
                self.entries.sort_by_key(|name| name.to_lowercase());
            }
            Err(e) => self.error = Some(format!("Cannot read {}: {e}", self.cwd.display())),
        }
        self.list_state.select(if self.entries.is_empty() {
            None
        } else {
            Some(0)
        });
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> DirPickerStep {
        // While naming a new folder, keys edit the name.
        if let Some(name) = &mut self.new_name {
            match key.code {
                KeyCode::Enter => {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        self.error = Some("Enter a folder name".to_string());
                        return DirPickerStep::Stay;
                    }
                    let path = self.cwd.join(&name);
                    match std::fs::create_dir(&path) {
                        Ok(()) => {
                            self.new_name = None;
                            self.cwd = path;
                            self.refresh();
                        }
                        Err(e) => {
                            self.error = Some(format!("Cannot create {}: {e}", path.display()));
                        }
                    }
                }
                KeyCode::Esc => {
                    self.new_name = None;
                    self.error = None;
                }
                _ => {
                    widgets::edit_line(name, &mut self.name_cursor, &key);
                }
            }
            return DirPickerStep::Stay;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
            KeyCode::Enter | KeyCode::Right => {
                if let Some(i) = self.list_state.selected()
                    && let Some(name) = self.entries.get(i)
                {
                    self.cwd = self.cwd.join(name);
                    self.refresh();
                }
            }
            KeyCode::Left | KeyCode::Backspace => {
                if let Some(parent) = self.cwd.parent() {
                    self.cwd = parent.to_path_buf();
                    self.refresh();
                }
            }
            KeyCode::Char('n') => {
                self.new_name = Some(String::new());
                self.name_cursor = 0;
                self.error = None;
            }
            KeyCode::Char('.') => {
                self.show_hidden = !self.show_hidden;
                self.refresh();
            }
            KeyCode::Tab | KeyCode::Char('s') => {
                return DirPickerStep::Choose(self.cwd.clone());
            }
            KeyCode::Esc => return DirPickerStep::Back,
            _ => {}
        }
        DirPickerStep::Stay
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        let [header, list_area, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(3),
        ])
        .areas(area);

        f.render_widget(
            Paragraph::new(format!(
                "Where should the received file be saved? — {}",
                self.cwd.display()
            ))
            .bold(),
            header,
        );

        if let Some(error) = &self.error
            && self.new_name.is_none()
        {
            f.render_widget(Paragraph::new(error.as_str()).red(), list_area);
        } else if self.entries.is_empty() {
            f.render_widget(Paragraph::new("(no subdirectories)").dim(), list_area);
        } else {
            let items: Vec<ListItem> = self
                .entries
                .iter()
                .map(|name| {
                    ListItem::new(format!(" {name}/"))
                        .style(Style::default().add_modifier(Modifier::BOLD))
                })
                .collect();
            let list =
                List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(list, list_area, &mut self.list_state);
        }

        let [input_row, summary_row, hint_row] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(footer);

        if let Some(name) = &self.new_name {
            widgets::input_line(f, input_row, "New folder name: ", name, self.name_cursor);
            if let Some(error) = &self.error {
                widgets::error_line(f, summary_row, error);
            }
            f.render_widget(Paragraph::new("Enter create · Esc cancel").dim(), hint_row);
        } else {
            f.render_widget(
                Paragraph::new(format!("Save into: {}", self.cwd.display())),
                summary_row,
            );
            f.render_widget(
                Paragraph::new(
                    "↑/↓ move · Enter open · ←/Backspace up · n new folder · . hidden · Tab use this directory · Esc back",
                )
                .dim(),
                hint_row,
            );
        }
    }
}
