#[derive(Debug, Clone, PartialEq)]
pub struct DisplayInfo {
    pub id: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_milli: u32,
    pub rotation_degrees: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    EmptyId,
    InvalidGeometry,
    UnknownDisplay,
    InvalidCoordinate,
}

#[derive(Debug, Default)]
pub struct DisplayTopology {
    displays: Vec<DisplayInfo>,
    selected: Option<String>,
}

impl DisplayTopology {
    pub fn replace(&mut self, displays: Vec<DisplayInfo>) -> Result<(), DisplayError> {
        for display in &displays {
            if display.id.trim().is_empty()
                || display.width == 0
                || display.height == 0
                || display.scale_milli == 0
            {
                return Err(DisplayError::InvalidGeometry);
            }
        }
        let selected = self
            .selected
            .take()
            .filter(|id| displays.iter().any(|display| &display.id == id));
        self.displays = displays;
        self.selected =
            selected.or_else(|| self.displays.first().map(|display| display.id.clone()));
        Ok(())
    }

    pub fn select(&mut self, id: &str) -> Result<(), DisplayError> {
        if self.displays.iter().any(|display| display.id == id) {
            self.selected = Some(id.to_owned());
            Ok(())
        } else {
            Err(DisplayError::UnknownDisplay)
        }
    }

    pub fn selected(&self) -> Option<&DisplayInfo> {
        self.selected
            .as_deref()
            .and_then(|id| self.displays.iter().find(|display| display.id == id))
    }

    pub fn map_normalized(
        &self,
        display_id: &str,
        x: f64,
        y: f64,
    ) -> Result<(i32, i32), DisplayError> {
        if !x.is_finite()
            || !y.is_finite()
            || !(0.0..=1.0).contains(&x)
            || !(0.0..=1.0).contains(&y)
        {
            return Err(DisplayError::InvalidCoordinate);
        }
        let display = self
            .displays
            .iter()
            .find(|display| display.id == display_id)
            .ok_or(DisplayError::UnknownDisplay)?;
        Ok((
            display.x + (x * f64::from(display.width - 1)).round() as i32,
            display.y + (y * f64::from(display.height - 1)).round() as i32,
        ))
    }

    pub fn all(&self) -> &[DisplayInfo] {
        &self.displays
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_display_survives_hotplug_when_present() {
        let mut topology = DisplayTopology::default();
        topology
            .replace(vec![DisplayInfo {
                id: "primary".into(),
                x: 0,
                y: 0,
                width: 100,
                height: 50,
                scale_milli: 1000,
                rotation_degrees: 0,
            }])
            .expect("display list");
        topology.select("primary").expect("select");
        assert_eq!(topology.map_normalized("primary", 1.0, 1.0), Ok((99, 49)));
    }
}
