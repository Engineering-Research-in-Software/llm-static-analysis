def create_security_prompt(app_data):
    bridge_info = "\n".join([f"- Class: {b[0]}, JS Name: {b[1]}, Methods: {b[2]}" for b in app_data['bridges']])
    js_code = "\n---\n".join(app_data['js'][:5])

    return f"""
    ANALYSIS TASK: Android Hybrid App Security Audit
    APP: {app_data['app']}

    NATIVE INTERFACE (Java):
    {bridge_info}

    DISCOVERED JAVASCRIPT:
    {js_code}

    Based on the bridge methods and the JS code provided, identify potential 
    Information-Flow risks (e.g., PII leaks, XSS, or unauthorized native access).
    Output your analysis in a structured JSON format.
    """