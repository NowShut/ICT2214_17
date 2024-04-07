import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import make_pipeline as make_pipeline_imb
from joblib import dump

# Load the dataset
df = pd.read_csv('cybersecurity_attacks.csv', low_memory=False)


# Filter out 'Malware', 'DDoS', and 'Intrusion' data
filtered_df = df[~df['Attack Type'].isin(['Malware', 'DDoS', 'Intrusion'])]

# Assuming 'Payload Data' and 'Attack Type' are the correct column names
X = filtered_df['Payload Data']
y = filtered_df['Attack Type']

# Splitting the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

# Configuring the TfidfVectorizer
tfidf_vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1,5), min_df=5)

# Configuring the Logistic Regression model
logistic_regression_model = LogisticRegression(max_iter=1000)

# Building the pipeline with SMOTE and Logistic Regression within a TF-IDF vectorization process
pipeline = make_pipeline_imb(tfidf_vectorizer, SMOTE(random_state=42), logistic_regression_model)

# Fitting the model
pipeline.fit(X_train, y_train)

# Predicting the test set results
y_pred = pipeline.predict(X_test)

# Evaluating the model
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(classification_report(y_test, y_pred))

# Saving the model
dump(pipeline, 'attack_prediction_model.joblib')
