# importing libraries

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pickle

# Reading the dataset

ds = pd.read_csv("symptoms.csv")

# Train - Test - Split of dataset

from sklearn.model_selection import train_test_split

x = ds.drop("type",axis=1)
y = ds["type"]

X_train,X_test,Y_train,Y_test = train_test_split(x,y,test_size=0.20,random_state=0)

# Model Fitting

from sklearn.metrics import accuracy_score 

# Applying Algorithm

from sklearn.naive_bayes import GaussianNB

nb = GaussianNB()

nb.fit(X_train,Y_train)

Y_pred_nb = nb.predict(X_test)




# Saving model to disk

pickle.dump(nb, open('suggestmodel.pkl','wb'))

# Loading model to compare the results

model = pickle.load(open('suggestmodel.pkl','rb'))
result = model.score(X_test, Y_test)
print(result)


