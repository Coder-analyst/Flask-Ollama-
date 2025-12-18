import streamlit as st
import pandas as pd
import plotly.express as px
import glob
import os

st.title('📊 Red Teaming Dashboard')
st.caption(f"Analyzing Security Performance for Local Model")

# Find the latest results file
list_of_files = glob.glob('results/red_team_log_*.csv') 
if list_of_files:
    latest_file = max(list_of_files, key=os.path.getctime)
    CSV_PATH = latest_file
    st.sidebar.success(f"Loaded Report: {os.path.basename(latest_file)}")
else:
    CSV_PATH = None

try:
    if CSV_PATH is None:
        raise FileNotFoundError("No log files found")
        
    df = pd.read_csv(CSV_PATH)

    # Metrics
    total_tests = len(df)
    total_blocked = df['blocked_input'].sum()
    block_rate = (total_blocked / total_tests) * 100
    
    st.header(f'🛡️ Security Score: {block_rate:.1f}%')
    st.metric(label="Total Attacks Blocked", value=f"{total_blocked}/{total_tests}", delta=f"{block_rate:.1f}% Block Rate")
    
    # Charts
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Input Block Analysis")
        df['block_status'] = df['blocked_input'].apply(lambda x: 'BLOCKED' if x else 'SLIPPED THROUGH')
        fig = px.pie(df, names='block_status', title='Proportion of Attacks Blocked', color='block_status',
                     color_discrete_map={'BLOCKED': 'green', 'SLIPPED THROUGH': 'red'})
        st.plotly_chart(fig, use_container_width=True)
        
    with c2:
        st.subheader("Risk Scores")
        fig2 = px.bar(df, x='attack_type', y='input_score', color='block_status', title='Risk Score per Attack')
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Detailed Logs")
    st.dataframe(df[['prompt_text', 'blocked_input', 'input_score', 'model_response']])

except FileNotFoundError:
    st.error("No results found. Please run 'python main.py' first!")
