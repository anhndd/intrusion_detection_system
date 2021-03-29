import csv
import numpy as np
from normalization import nomalizeUNSW_NB15
from normalization import isColab
from keras.models import Sequential
from keras.layers import Dense
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
import pickle
from pathlib import Path

trainingFilename = "UNSW_NB15_training-set.csv"
testFilename = "UNSW_NB15_testing-set.csv"
if isColab:
    trainingFilename = "/content/drive/My Drive/Colab Notebooks/training_projectM1/UNSW_NB15_training-set.csv"
    testFilename = "/content/drive/My Drive/Colab Notebooks/training_projectM1/UNSW_NB15_testing-set.csv"


def readData(file, X, Y):
    for row in file:
        x = [x for x in row[1:len(row) - 2]]
        y = row[-2]
        x, y = nomalizeUNSW_NB15(x, y)
        X.append(x)
        Y.append(y)
    X = np.array(X)
    Y = np.array(Y)

    return X, Y


def model_RandomForest(X_train, Y_train):
    filename = 'randomForestModel.sav'
    f = Path(filename)
    if f.is_file():
        return pickle.load(open(filename, 'rb'))
    else:
        model = RandomForestClassifier(verbose=0, warm_start=True)
        model.fit(X_train, Y_train)
        pickle.dump(model, open(filename, 'wb'))
        return model

def model_DecisionTree(X_train, Y_train):
    filename = 'decisionTree.sav'
    f = Path(filename)
    if f.is_file():
        return pickle.load(open(filename, 'rb'))
    else:
        model = DecisionTreeClassifier()
        model.fit(X_train, Y_train)
        pickle.dump(model, open(filename, 'wb'))
        return model

if __name__ == '__main__':
    start_time = time.clock()
    train_file = csv.reader(open(trainingFilename, "rt"))
    next(train_file)
    test_file = csv.reader(open(testFilename, "rt"))
    next(test_file)
    X_train = []
    Y_train = []
    X_test = []
    Y_test = []

    X_train, Y_train = readData(train_file, X_train, Y_train)
    X_test, Y_test = readData(test_file, X_test, Y_test)

    # # Random Forest
    # model = model_RandomForest(X_train, Y_train)
    # print("accuracy:", model.score(X_test, Y_test) * 100, "%")
    #
    # # Decision Tree
    # model = model_DecisionTree(X_train, Y_train)
    # print("accuracy:", model.score(X_test, Y_test) * 100, "%")

    model = Sequential()
    model.add(Dense(len(X_train[0]),activation='sigmoid', input_shape=(len(X_train[0]),)))
    model.add(Dense(10,activation='sigmoid'))
    model.compile(loss='sparse_categorical_crossentropy',optimizer='sgd', metrics=['accuracy'])

    model.fit(X_train, Y_train, epochs=2, verbose=0)

    y = model.predict(X_train[0])
    print(y)
    _, acc = model.evaluate(X_test, Y_test)
    print(Y_test)
    for y in Y_test:
        if y != 0:
            print(y)
    print("accuracy:", acc * 100, "%")
    print(time.clock() - start_time, "seconds")
