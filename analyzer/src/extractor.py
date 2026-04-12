import os
import sqlite3
import pandas as pd


class DataExtractor:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db_stem = os.path.splitext(os.path.basename(db_path))[0]

    def get_all_apps(self) -> list[str]:
        with sqlite3.connect(self.db_path) as conn:
            query = "SELECT DISTINCT appName FROM webview_new"
            df = pd.read_sql_query(query, conn)
            return df["appName"].tolist()

    def get_all_callsites(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            query = (
                "SELECT id, appName, bridgeClass, intefaceObject, bridgeMethods, initiatingMethod "
                "FROM webview_new"
            )
            df = pd.read_sql_query(query, conn)
            return df.to_dict(orient="records")

    def get_callsite_context(self, callsite_id: int) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            row_df = pd.read_sql_query(
                "SELECT id, appName, bridgeClass, intefaceObject, bridgeMethods, initiatingMethod "
                "FROM webview_new WHERE id = ?",
                conn,
                params=(callsite_id,),
            )

            if row_df.empty:
                raise ValueError(f"No callsite found with id={callsite_id}")

            row = row_df.iloc[0]
            app_name = str(row["appName"])

            js_df = pd.read_sql_query(
                "SELECT PASS_STRING, confidence, resolution_type FROM jsdetails WHERE PACKAGE_NAME = ?",
                conn,
                params=(app_name,),
            )

        return {
            "callsite_id": int(row["id"]),
            "db_stem": self.db_stem,
            "app_name": app_name,
            "bridge": {
                "bridgeClass": row["bridgeClass"],
                "intefaceObject": row["intefaceObject"],
                "bridgeMethods": row["bridgeMethods"],
                "initiatingMethod": row["initiatingMethod"],
            },
            "js_snippets": js_df.to_dict(orient="records")[:10],
        }

    def get_app_context(self, app_name: str) -> dict:
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
            "bridges": bridges.to_dict(orient="records"),
            "js_snippets": js_facts.to_dict(orient="records"),
        }
