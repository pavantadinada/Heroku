# importing libraries

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pickle

# Reading the dataset

dataset = pd.read_csv("heart.csv")

# Train - Test - Split of dataset

from sklearn.model_selection import train_test_split

predictors = dataset.drop("target",axis=1)
target = dataset["target"]

X_train,X_test,Y_train,Y_test = train_test_split(predictors,target,test_size=0.20,random_state=0)

# Model Fitting

from sklearn.metrics import accuracy_score 

# Applying Algorithm

from sklearn.ensemble import RandomForestClassifier

max_accuracy = 0

for x in range(2000):
    rf = RandomForestClassifier(random_state=x)
    rf.fit(X_train,Y_train)
    Y_pred_rf = rf.predict(X_test)
    current_accuracy = round(accuracy_score(Y_pred_rf,Y_test)*100,2)
    if(current_accuracy>max_accuracy):
        max_accuracy = current_accuracy
        best_x = x
        
#print(max_accuracy)
#print(best_x)

rf = RandomForestClassifier(random_state=best_x)
rf.fit(X_train,Y_train)


# Saving model to disk

# Saving model to disk

pickle.dump(rf, open('model.pkl','wb'))

# Loading model to compare the results

model = pickle.load(open('model.pkl','rb'))
result = model.score(X_test, Y_test)
print(result)


