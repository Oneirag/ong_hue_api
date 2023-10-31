import pandas as pd
import numpy as np


df = pd.DataFrame(np.arange(103), columns=["number"])
df['square'] = df['number'] ** 2
df['cube'] = df['number'] ** 3
df.to_csv("ong_hive_test.csv", index=False)
