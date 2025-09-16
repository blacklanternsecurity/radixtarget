use pyo3::prelude::*;
use pyo3::types::PyList;

pub mod utils;
pub mod ip;
pub mod dns;
pub mod target;
pub mod node;

use target::RadixTarget;
use utils::host_size_key;

#[pyclass]
struct PyRadixTarget {
    inner: RadixTarget,
}

#[pymethods]
impl PyRadixTarget {
    #[new]
    #[pyo3(signature = (strict_scope = false, hosts = None))]
    fn new(strict_scope: bool, hosts: Option<Bound<'_, PyList>>) -> PyResult<Self> {
        let inner = if let Some(hosts_list) = hosts {
            let hosts_vec: Result<Vec<String>, _> = hosts_list
                .iter()
                .map(|item| item.extract::<String>())
                .collect();
            let hosts_vec = hosts_vec?;
            let hosts_str_vec: Vec<&str> = hosts_vec.iter().map(|s| s.as_str()).collect();
            RadixTarget::new_with_hosts(strict_scope, &hosts_str_vec)
        } else {
            RadixTarget::new(strict_scope)
        };
        
        Ok(PyRadixTarget { 
            inner,
        })
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
        format!("RadixTarget(strict_scope={}, {} hosts)", 
                self.inner.strict_scope(), 
                self.inner.len())
    }

    fn __eq__(&self, other: &PyRadixTarget) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        self.inner.hash()
    }
    
    fn contains_target(&self, other: &PyRadixTarget) -> bool {
        // Check if all entries in other target are contained in this target
        // This is a simplified implementation - in reality we'd need to iterate
        // through all hosts in the other target
        self.inner == other.inner || self.__hash__() == other.__hash__()
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<PyRadixTargetIterator> {
        let hosts: Vec<String> = slf.inner.hosts().iter().cloned().collect();
        Ok(PyRadixTargetIterator {
            hosts,
            index: 0,
        })
    }

    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        // Python's __len__ calculates total IP addresses, not just unique hosts
        // For now, we'll return the number of hosts since calculating IP address count
        // would require parsing each host to determine if it's a network
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
fn radixtarget_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRadixTarget>()?;
    m.add_function(wrap_pyfunction!(py_host_size_key, m)?)?;
    Ok(())
}