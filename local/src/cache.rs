use std::{collections::HashMap, fs, io, ops::DerefMut, path::Path};

pub struct Cache(HashMap<String, String>);

impl std::ops::Deref for Cache {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Cache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Cache {
    pub fn open(path: impl AsRef<Path>) -> Cache {
        let Ok(file) = fs::read_to_string(path) else {
            eprintln!("Cached secrets not found creating");
            return Self(HashMap::new());
        };
        Self(
            file.split('\n')
                .flat_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    pub fn write(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let data: Vec<_> = self.0.iter().map(|(k, v)| format!("{k}={v}")).collect();
        fs::write(path, data.join("\n"))
    }
}
