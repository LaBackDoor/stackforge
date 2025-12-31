use pyo3::prelude::*;

#[pymodule]
fn stackforge(_py: Python, _m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
