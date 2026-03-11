import sqlite3
import pandas as pd

class DataExtractor:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_all_apps(self):
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT DISTINCT appName FROM webview_new"
            df = pd.read_sql_query(query, conn)
            return df['appName'].tolist()

    def get_app_context(self, app_name):
        with sqlite3.connect(self.db_path) as conn:
            bridge_query = """
                SELECT bridgeClass, intefaceObject, bridgeMethods, initiatingMethod 
                FROM webview_new WHERE appName = ?
            """
            bridges = pd.read_sql_query(bridge_query, conn, params=(app_name,))
            
            js_query = """
                SELECT PASS_STRING, confidence, resolution_type 
                FROM jsdetails WHERE PACKAGE_NAME = ?
            """
            js_facts = pd.read_sql_query(js_query, conn, params=(app_name,))
            
        return {
            "app_name": app_name,
            "bridges": bridges.to_dict(orient='records'),
            "js_snippets": js_facts.to_dict(orient='records')
        }