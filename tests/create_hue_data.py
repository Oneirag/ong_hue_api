import pandas as pd
import numpy as np
import os

df = pd.DataFrame(np.arange(103), columns=["number"])
df['square'] = df['number'] ** 2
df['cube'] = df['number'] ** 3
filename = "ong_hive_test.csv"
df.to_csv(filename, index=False, lineterminator="\n")
print(f"File {filename} generated with size {os.path.getsize(filename)}")