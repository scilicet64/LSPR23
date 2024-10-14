## Code Example for LSPR23: A novel IDS dataset from the largest live-fire cybersecurity exercise

This LSPR23 code example retrieves the dataset from Zenodo, performs some selections, and fits the data using benign and malicious labels into a Random Forest.

## LSPR23

LSPR23 is derived from Locked Shields 2023, a major live-fire cyber defense exercise. The dataset includes approximately 16 million network flows, of which approximately 1.6 million are labeled malicious.

## Configuration

In this example, we use a smaller selection of the data (`nFlows = 80000`) because the full dataset contains a total of 16,353,511 flows. Loading the entire dataset can be very memory-intensive. Adjust `nFlows` as needed based on your available system memory.

```python
nFlows = 80000
```

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/scilicet64/lspr23.git
    cd lspr23
    ```

2. **Create and activate a virtual environment**:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install the required packages**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Run the script**:
    ```sh
    python lspr23_code.py
    ```

## Citation

Please cite our research article when using our dataset:

> **LSPR23: A novel IDS dataset from the largest live-fire cybersecurity exercise**
> [https://doi.org/10.1016/j.jisa.2024.103847](https://doi.org/10.1016/j.jisa.2024.103847)

Please also cite the dataset itself on Zenodo:

> **Locked Shields Partners Run 23 (LSPR23): A novel IDS dataset from the largest live-fire cybersecurity exercise**
> [https://doi.org/10.5281/zenodo.8042347](https://doi.org/10.5281/zenodo.8042347)

