import zenodo_get
import os
from zipfile import ZipFile
import pandas
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
import hashlib
import time
cite = """
Please cite our research paper which describes the LSPR23 dataset:
@article{DIJK2024103847,
title = {LSPR23: A novel IDS dataset from the largest live-fire cybersecurity exercise},
journal = {Journal of Information Security and Applications},
volume = {85},
pages = {103847},
year = {2024},
issn = {2214-2126},
doi = {https://doi.org/10.1016/j.jisa.2024.103847},
url = {https://www.sciencedirect.com/science/article/pii/S2214212624001492},
author = {Allard Dijk and Emre Halisdemir and Cosimo Melella and Alari Schu and Mauno Pihelgas and Roland Meier},
keywords = {Cybersecurity components, Intrusion detection, IDS dataset, Artificial intelligence, Autonomous agents},
abstract = {Cybersecurity threats are constantly evolving and becoming increasingly sophisticated, automated, adaptive, and intelligent. This makes it difficult for organizations to defend their digital assets. Industry professionals are looking for solutions to improve the efficiency and effectiveness of cybersecurity operations, adopting different strategies. In cybersecurity, the importance of developing new intrusion detection systems (IDSs) to address these threats has emerged. Most of these systems today are based on machine learning. But these systems need high-quality data to “learn” the characteristics of malicious traffic. Such datasets are difficult to obtain and therefore rarely available. This paper advances the state of the art and presents a new high-quality IDS dataset. The dataset originates from Locked Shields, one of the world’s most extensive live-fire cyber defense exercises. This ensures that (i) it contains realistic behavior of attackers and defenders; (ii) it contains sophisticated attacks; and (iii) it contains labels, as the actions of the attackers are well-documented. The dataset includes approximately 16 million network flows, [F3] of which approximately 1.6 million were labeled malicious. What is unique about this dataset is the use of a new labeling technique that increases the accuracy level of data labeling. We evaluate the robustness of our dataset using both quantitative and qualitative methodologies. We begin with a quantitative examination of the Suricata IDS alerts based on signatures and anomalies. Subsequently, we assess the reproducibility of machine learning experiments conducted by Känzig et al., who used a private Locked Shields dataset. We also apply the quality criteria outlined by the evaluation framework proposed by Gharib et al. Using our dataset with an existing classifier, we demonstrate comparable results (F1 score of 0.997) to the original paper where the classifier was evaluated on a private dataset (F1 score of 0.984)}
}

Please also cite the dataset itself on Zenodo:
@dataset{dijk_2024_8042347,
  author       = {Dijk, Allard and Halisdemir, Emre and Melella, Cosimo and Schu, Alari and Pihelgas, Mauno and Meier, Roland},
  title        = {{Locked Shields Partners Run 23 (LSPR23): A novel IDS dataset from the largest live-fire cybersecurity exercise}},
  month        = aug,
  year         = 2024,
  publisher    = {Zenodo},
  version      = 1,
  doi          = {10.5281/zenodo.8042347},
  url          = {https://doi.org/10.5281/zenodo.8042347}
}
"""
nFlows = 80000  # Totally 16,353,511 Flows available
flow_selection = "flow_selection.csv"
nrOfRowsFound = 0

if nFlows> 16353511:
    nFlows= 16353511

dtype_dict = {
    'Flow ID':'str',
    'SrcIP': 'str',
    'DstIP': 'str',
    'Conn_state': 'str',
    'Service': 'str',
    'Segment_src': 'str',
    'Segment_dst': 'str',
    'Expoid_src': 'str',
    'Expoid_dst': 'str'
}

if os.path.exists(flow_selection):
    try:
        df = pandas.read_csv(flow_selection, nrows=nFlows, dtype=dtype_dict)
        nrOfRowsFound = df.shape[0]
    except:
        nrOfRowsFound = 0

if nrOfRowsFound < nFlows:
    print(f"Constructing new {flow_selection} with {nFlows} flows")
    flow_zipfile = "ls23pr_flows.zip"
    if not os.path.exists(flow_zipfile):
        print(cite) #only print first time when getting the Zenodo dataset
        zenodo_get.zenodo_get(argv=["-r 8042347"])
    flow_selection_fp = open(flow_selection,"w")
    if os.path.exists(flow_zipfile):
        with ZipFile(flow_zipfile, 'r') as zObject:
            for name in zObject.namelist():
                nCount=-1 # to skip the header
                for line in zObject.open(name):
                    flow_selection_fp.write(line.decode())
                    nCount+=1
                    if nCount == nFlows:
                        break

            flow_selection_fp.close()
            zObject.close()
    if os.path.exists(flow_selection):
        df = pandas.read_csv(flow_selection,nrows=nFlows, dtype=dtype_dict)
        nrOfRowsFound = df.shape[0]
        print(f"Created new {flow_selection}")


def hash_text(textualinfo):
    if pandas.isna(textualinfo):
        textualinfo=""
    return int(hashlib.sha256(textualinfo.encode()).hexdigest(), 16) % (10**8)




# Apply hashing function to necessary columns, to convert text to a number for classification
for col in dtype_dict.keys():
    df[f'{col}_hash'] = df[col].apply(hash_text)

df = df.drop(['Flow ID','SrcIP','DstIP', 'Conn_state','Service','Segment_src','Segment_dst','Expoid_src','Expoid_dst'],axis=1) # dropping textual columns from dataframe
X = df.drop(['Label_src','Label_dst','Label'],axis=1)

X.replace([np.inf, -np.inf], np.nan, inplace=True)

y = df['Label']
label_counts = df['Label'].value_counts()
print(f"Label count\nBenign {label_counts.get(0)}\nMalicious {label_counts.get(1)}")

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
y_train_label_counts = y_train.value_counts()
y_test_label_counts = y_test.value_counts()
print(f"Labels in training: Benign: {y_train_label_counts.get(0)} Malicious: {y_train_label_counts.get(1)}  ")
print(f"Labels in test {y_test_label_counts.get(0)} Malicious: {y_test_label_counts.get(1)}  ")

# Initialize the RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100, random_state=42)

print("training...")
start = time.time()
# Train the model
rf.fit(X_train, y_train)
print(f"End of training in {time.time()-start} seconds")

# Predict on the test set
y_pred = rf.predict(X_test)

# Calculate the F1 score
f1 = f1_score(y_test, y_pred, average='weighted')
print(f'F1 Score: {f1}')