from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from keras.models import model_from_json
from sklearn.metrics import classification_report
from tensorflow import keras

number_of_label = 5
type_of_model = 'model_mlp_five'
# type_of_model = 'model_lstm_two'

# Label list: 5 or 2
if type_of_model == 'model_mlp_five':
    label_list = ["normal", "dos", "probe", "u2r", "r2l"]
    number_of_label = 5
    model = keras.models.load_model("model_mlp_five.h5")
elif type_of_model == 'model_lstm_two':
    label_list = ["normal", "abnormal"]
    number_of_label = 2
    model = keras.models.load_model("model_lstm_two.h5")

training_path = "KDD_Train.csv"
df_train = pd.read_csv(filepath_or_buffer=training_path, header=None, delimiter=",")
df_train.drop(labels=[41,42], inplace=True, axis=1)

# Column 1, 2, and 3 are object
def encodeFeature(df):
    categorical_feature = [1, 2, 3]
    df_feature = df.copy()
    for feature in categorical_feature:
        df_feature[feature] = df[feature].astype('category').cat.codes
    df_feature = df_feature.astype(float)
    return df_feature


df_feature = encodeFeature(df_train)
scaler = MinMaxScaler()
scaler.fit(df_feature)


def normalize(data):
    new_data_scaled = scaler.transform(data)
    return new_data_scaled

def predict_data(X_predict):
    # Get new data

    # TODO: Get full path of KDD training file
    if len(X_predict) > 0:
        data = pd.DataFrame(data=X_predict[:, :], index=None, columns=None)
        data = encodeFeature(data)
        data_scaled = normalize(data)

        if type_of_model == 'model_lstm_two':
            data_scaled = np.reshape(data_scaled, (data_scaled.shape[0], 1, data_scaled.shape[1])) # Reshape for data_scaled

        Y_pred = model.predict(data_scaled)

        Y_result = []
        for elem in Y_pred:
            assert len(elem) == number_of_label
            outcome = np.argmax(elem)
            # print(label_list[outcome])
            Y_result.append(label_list[outcome])
        return Y_result
