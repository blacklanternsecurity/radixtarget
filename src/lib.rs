use pyo3::prelude::*;
use pyo3::types::PyList;

pub mod dns;
pub mod ip;
pub mod node;
pub mod target;
pub mod utils;

pub use dns::ScopeMode;
pub use target::RadixTarget;
use utils::host_size_key;

#[pyclass]
struct PyRadixTarget {
    inner: RadixTarget,
}

#[pymethods]
impl PyRadixTarget {
    #[new]
    #[pyo3(signature = (hosts = None, strict_scope = false, acl_mode = false))]
    fn new(hosts: Option<Bound<'_, PyList>>, strict_scope: bool, acl_mode: bool) -> PyResult<Self> {
        let scope_mode = match (strict_scope, acl_mode) {
            (false, false) => ScopeMode::Normal,
            (true, false) => ScopeMode::Strict,
            (false, true) => ScopeMode::Acl,
            (true, true) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "strict_scope and acl_mode are mutually exclusive",
                ));
            }
        };
        let mut inner = RadixTarget::new(&[], scope_mode);
        if let Some(hosts_list) = hosts {
            for host in hosts_list.iter() {
                inner.insert(&host.extract::<String>()?);
            }
        }
        Ok(PyRadixTarget { inner })
    }

    fn insert(&mut self, value: &str) -> Option<String> {
        self.inner.insert(value)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn contains(&self, value: &str) -> bool {
        self.inner.contains(value)
    }

    fn delete(&mut self, value: &str) -> bool {
        self.inner.delete(value)
    }

    fn get(&self, value: &str) -> Option<String> {
        self.inner.get(value)
    }

    fn prune(&mut self) -> usize {
        self.inner.prune()
    }

    fn defrag(&mut self) -> (Vec<String>, Vec<String>) {
        let (cleaned, new) = self.inner.defrag();
        (cleaned.into_iter().collect(), new.into_iter().collect())
    }

    fn __repr__(&self) -> String {
        format!(
            "RadixTarget(strict_scope={}, {} hosts)",
            self.inner.strict_scope(),
            self.inner.len()
        )
    }

    fn __eq__(&self, other: &PyRadixTarget) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        self.inner.hash()
    }

    fn contains_target(&self, other: &PyRadixTarget) -> bool {
        self.inner.contains_target(&other.inner)
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<PyRadixTargetIterator> {
        let hosts: Vec<String> = slf.inner.hosts().iter().cloned().collect();
        Ok(PyRadixTargetIterator { hosts, index: 0 })
    }

    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __str__(&self) -> String {
        let mut hosts: Vec<String> = self.inner.hosts().iter().cloned().collect();
        hosts.sort();

        if hosts.len() <= 5 {
            hosts.join(",")
        } else {
            format!("{},…", hosts[..5].join(","))
        }
    }

    fn copy(&self) -> PyRadixTarget {
        PyRadixTarget {
            inner: self.inner.copy(),
        }
    }
}

#[pyclass]
struct PyRadixTargetIterator {
    hosts: Vec<String>,
    index: usize,
}

#[pymethods]
impl PyRadixTargetIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<String> {
        if self.index < self.hosts.len() {
            let result = self.hosts[self.index].clone();
            self.index += 1;
            Some(result)
        } else {
            None
        }
    }
}

/// PyO3 wrapper for the host_size_key function
#[pyfunction]
fn py_host_size_key(host: &Bound<'_, pyo3::PyAny>) -> PyResult<(i64, String)> {
    // Convert the input to string - this handles both str and ipaddress objects
    let host_str = host.str()?.to_string();
    Ok(host_size_key(&host_str))
}

#[pymodule]
fn _radixtarget(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRadixTarget>()?;
    m.add_function(wrap_pyfunction!(py_host_size_key, m)?)?;
    Ok(())
}
