import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
import json

# Page configuration
st.set_page_config(
    page_title="SABSA Security Architecture Framework",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS to match the original interface
st.markdown("""
<style>
    .main-header {
        font-size: 2rem;
        color: #1f4e79;
        text-align: center;
        margin-bottom: 1rem;
    }
    .node-card {
        background-color: #ffffff;
        border: 2px solid #4472c4;
        border-radius: 8px;
        padding: 8px;
        margin: 4px;
        text-align: center;
        font-size: 12px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .layer-header {
        background-color: #2c5aa0;
        color: white;
        padding: 8px;
        border-radius: 6px;
        text-align: center;
        font-weight: bold;
        margin: 10px 0;
    }
    .process-node {
        background-color: #f0f8ff;
        border: 1px solid #87ceeb;
        border-radius: 50%;
        width: 80px;
        height: 80px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 10px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Exact data structure from the image
@st.cache_data
def load_framework_data():
    # Main domain nodes (top level)
    main_domains = {
        "Data Security": {"x": 1, "y": 5, "color": "#4472c4"},
        "Identity & Access Management": {"x": 3, "y": 5, "color": "#4472c4"},
        "Incident Handling & Response": {"x": 5, "y": 5, "color": "#4472c4"},
        "Vulnerability Management": {"x": 7, "y": 5, "color": "#4472c4"},
        "Security Risk Management": {"x": 9, "y": 5, "color": "#4472c4"}
    }
    
    # Secondary level nodes
    secondary_nodes = {
        # Data Security branch
        "Data Devaluation": {"x": 0.5, "y": 4, "color": "#5b9bd5", "parent": "Data Security"},
        "Data Integrity": {"x": 1, "y": 4, "color": "#5b9bd5", "parent": "Data Security"},
        "Data Confidentiality": {"x": 1.5, "y": 4, "color": "#5b9bd5", "parent": "Data Security"},
        "Security Testing": {"x": 1, "y": 3, "color": "#5b9bd5", "parent": "Data Security"},
        
        # Identity & Access Management branch
        "Authentication": {"x": 2.5, "y": 4, "color": "#5b9bd5", "parent": "Identity & Access Management"},
        "Authorization": {"x": 3, "y": 4, "color": "#5b9bd5", "parent": "Identity & Access Management"},
        "Access Recertification": {"x": 3.5, "y": 4, "color": "#5b9bd5", "parent": "Identity & Access Management"},
        "Vulnerability Identification": {"x": 3, "y": 3, "color": "#5b9bd5", "parent": "Identity & Access Management"},
        
        # Incident Handling & Response branch
        "Remediation Management": {"x": 4.5, "y": 4, "color": "#5b9bd5", "parent": "Incident Handling & Response"},
        "Preparation": {"x": 5, "y": 4, "color": "#5b9bd5", "parent": "Incident Handling & Response"},
        "Recovery": {"x": 5.5, "y": 4, "color": "#5b9bd5", "parent": "Incident Handling & Response"},
        "Incident Communication": {"x": 5, "y": 3, "color": "#5b9bd5", "parent": "Incident Handling & Response"},
        
        # Vulnerability Management branch
        "Strategic Planning": {"x": 6.5, "y": 4, "color": "#5b9bd5", "parent": "Vulnerability Management"},
        "Change Management": {"x": 7, "y": 4, "color": "#5b9bd5", "parent": "Vulnerability Management"},
        "Security Risk Integration": {"x": 7.5, "y": 4, "color": "#5b9bd5", "parent": "Vulnerability Management"},
        
        # Security Risk Management branch
        "Governance & Reporting": {"x": 8.5, "y": 4, "color": "#5b9bd5", "parent": "Security Risk Management"},
        "Security Services Management": {"x": 9, "y": 4, "color": "#5b9bd5", "parent": "Security Risk Management"}
    }
    
    # Process level nodes (circular nodes at bottom)
    process_nodes = {
        # Row 1 processes
        "Encryption": {"x": 0.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Masking": {"x": 1, "y": 2, "color": "#8faadc", "type": "process"},
        "Anonymization": {"x": 1.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Disclosure Authorization": {"x": 2, "y": 2, "color": "#8faadc", "type": "process"},
        "Validation": {"x": 2.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Digital Signing": {"x": 3, "y": 2, "color": "#8faadc", "type": "process"},
        "Multi-factor Authentication": {"x": 3.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Vulnerability Analysis": {"x": 4, "y": 2, "color": "#8faadc", "type": "process"},
        "Estimation of Extend": {"x": 4.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Recovery Analysis": {"x": 5, "y": 2, "color": "#8faadc", "type": "process"},
        "Classification of Vulnerabilities and ...": {"x": 5.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Events History Repository": {"x": 6, "y": 2, "color": "#8faadc", "type": "process"},
        "Wargaming": {"x": 6.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Maturity Frameworks": {"x": 7, "y": 2, "color": "#8faadc", "type": "process"},
        "Incident Response Planning": {"x": 7.5, "y": 2, "color": "#8faadc", "type": "process"},
        "Risk Appetite": {"x": 8, "y": 2, "color": "#8faadc", "type": "process"},
        
        # Row 2 processes
        "Secure Repository": {"x": 0.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Inventory of Basic Accounts and...": {"x": 1, "y": 1, "color": "#8faadc", "type": "process"},
        "Control of Privileged Access": {"x": 1.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Sandbox": {"x": 2, "y": 1, "color": "#8faadc", "type": "process"},
        "Training": {"x": 2.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Role/Rule Management": {"x": 3, "y": 1, "color": "#8faadc", "type": "process"},
        "Single Sign On": {"x": 3.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Remote Access Authentication": {"x": 4, "y": 1, "color": "#8faadc", "type": "process"},
        "Monitoring and Qualification of...": {"x": 4.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Business Alignment": {"x": 5, "y": 1, "color": "#8faadc", "type": "process"},
        "Incident Escalation": {"x": 5.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Change Management": {"x": 6, "y": 1, "color": "#8faadc", "type": "process"},
        "Metrics, KPIs, KRIs and MI": {"x": 6.5, "y": 1, "color": "#8faadc", "type": "process"},
        "Secure Transition": {"x": 7, "y": 1, "color": "#8faadc", "type": "process"},
        "Strategy": {"x": 7.5, "y": 1, "color": "#8faadc", "type": "process"},
        
        # Row 3 processes
        "Security Testing Framework": {"x": 0.5, "y": 0, "color": "#8faadc", "type": "process"},
        "Penetration Testing": {"x": 1, "y": 0, "color": "#8faadc", "type": "process"},
        "Attestation": {"x": 1.5, "y": 0, "color": "#8faadc", "type": "process"},
        "Automated testing": {"x": 2, "y": 0, "color": "#8faadc", "type": "process"},
        "Recertification": {"x": 2.5, "y": 0, "color": "#8faadc", "type": "process"},
        "Authenticated Scanning": {"x": 3, "y": 0, "color": "#8faadc", "type": "process"},
        "Red Team Testing": {"x": 3.5, "y": 0, "color": "#8faadc", "type": "process"},
        "Service Catalogue": {"x": 4, "y": 0, "color": "#8faadc", "type": "process"},
        "Change Reconciliation": {"x": 4.5, "y": 0, "color": "#8faadc", "type": "process"},
        "Case Management": {"x": 5, "y": 0, "color": "#8faadc", "type": "process"}
    }
    
    # Connection mappings (simplified for visualization)
    connections = []
    
    # Connect main domains to secondary nodes
    for secondary, data in secondary_nodes.items():
        if data["parent"] in main_domains:
            connections.append((data["parent"], secondary))
    
    # Connect secondary nodes to some process nodes (sample connections)
    secondary_to_process = [
        ("Data Integrity", "Encryption"),
        ("Data Confidentiality", "Masking"),
        ("Authentication", "Multi-factor Authentication"),
        ("Authorization", "Role/Rule Management"),
        ("Preparation", "Incident Response Planning"),
        ("Recovery", "Business Alignment"),
        ("Strategic Planning", "Wargaming"),
        ("Change Management", "Change Management"),
        ("Security Services Management", "Metrics, KPIs, KRIs and MI")
    ]
    
    connections.extend(secondary_to_process)
    
    return main_domains, secondary_nodes, process_nodes, connections

def create_interactive_framework():
    st.markdown('<h1 class="main-header">🔒 SABSA Security Architecture Framework</h1>', unsafe_allow_html=True)
    
    # Load data
    main_domains, secondary_nodes, process_nodes, connections = load_framework_data()
    
    # Control panel
    st.sidebar.title("Framework Controls")
    
    # View options
    show_connections = st.sidebar.checkbox("Show Connections", value=True)
    show_labels = st.sidebar.checkbox("Show Node Labels", value=True)
    highlight_domain = st.sidebar.selectbox("Highlight Domain", 
                                          ["None"] + list(main_domains.keys()))
    
    # Create the main visualization
    fig = go.Figure()
    
    # Add connections first (so they appear behind nodes)
    if show_connections:
        for connection in connections:
            start_node = connection[0]
            end_node = connection[1]
            
            # Find coordinates
            start_coords = None
            end_coords = None
            
            if start_node in main_domains:
                start_coords = (main_domains[start_node]["x"], main_domains[start_node]["y"])
            elif start_node in secondary_nodes:
                start_coords = (secondary_nodes[start_node]["x"], secondary_nodes[start_node]["y"])
            elif start_node in process_nodes:
                start_coords = (process_nodes[start_node]["x"], process_nodes[start_node]["y"])
            
            if end_node in main_domains:
                end_coords = (main_domains[end_node]["x"], main_domains[end_node]["y"])
            elif end_node in secondary_nodes:
                end_coords = (secondary_nodes[end_node]["x"], secondary_nodes[end_node]["y"])
            elif end_node in process_nodes:
                end_coords = (process_nodes[end_node]["x"], process_nodes[end_node]["y"])
            
            if start_coords and end_coords:
                fig.add_trace(go.Scatter(
                    x=[start_coords[0], end_coords[0]], 
                    y=[start_coords[1], end_coords[1]],
                    mode='lines',
                    line=dict(color='rgba(100,100,100,0.3)', width=1),
                    showlegend=False,
                    hoverinfo='none'
                ))
    
    # Add main domain nodes
    main_x = [data["x"] for data in main_domains.values()]
    main_y = [data["y"] for data in main_domains.values()]
    main_names = list(main_domains.keys())
    main_colors = [main_domains[name]["color"] for name in main_names]
    
    # Highlight selected domain
    if highlight_domain != "None":
        main_colors = ['#ff6b6b' if name == highlight_domain else '#cccccc' for name in main_names]
    
    fig.add_trace(go.Scatter(
        x=main_x, y=main_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(size=60, color=main_colors, 
                   line=dict(width=2, color='white')),
        text=main_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=9, color='white'),
        name="Main Domains",
        hovertemplate='<b>%{text}</b><br>Domain Type: Main<extra></extra>'
    ))
    
    # Add secondary nodes
    sec_x = [data["x"] for data in secondary_nodes.values()]
    sec_y = [data["y"] for data in secondary_nodes.values()]
    sec_names = list(secondary_nodes.keys())
    sec_colors = [secondary_nodes[name]["color"] for name in sec_names]
    
    # Highlight if parent domain is selected
    if highlight_domain != "None":
        sec_colors = ['#ff9999' if secondary_nodes[name]["parent"] == highlight_domain 
                     else '#dddddd' for name in sec_names]
    
    fig.add_trace(go.Scatter(
        x=sec_x, y=sec_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(size=45, color=sec_colors,
                   line=dict(width=1, color='white')),
        text=sec_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=8),
        name="Secondary Nodes",
        hovertemplate='<b>%{text}</b><br>Domain Type: Secondary<br>Parent: %{customdata}<extra></extra>',
        customdata=[secondary_nodes[name]["parent"] for name in sec_names]
    ))
    
    # Add process nodes (circular)
    proc_x = [data["x"] for data in process_nodes.values()]
    proc_y = [data["y"] for data in process_nodes.values()]
    proc_names = list(process_nodes.keys())
    proc_colors = [process_nodes[name]["color"] for name in proc_names]
    
    fig.add_trace(go.Scatter(
        x=proc_x, y=proc_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(size=30, color=proc_colors,
                   line=dict(width=1, color='#666666'),
                   symbol='circle'),
        text=[name[:15] + '...' if len(name) > 15 else name for name in proc_names] if show_labels else None,
        textposition="middle center",
        textfont=dict(size=6),
        name="Process Nodes",
        hovertemplate='<b>%{text}</b><br>Domain Type: Process<extra></extra>'
    ))
    
    # Update layout to match the original
    fig.update_layout(
        title="SABSA Security Architecture Framework - Interactive View",
        xaxis=dict(
            showgrid=False,
            showticklabels=False,
            zeroline=False,
            range=[-0.5, 9.5]
        ),
        yaxis=dict(
            showgrid=False,
            showticklabels=False,
            zeroline=False,
            range=[-0.5, 5.5]
        ),
        plot_bgcolor='rgba(240,248,255,0.8)',
        paper_bgcolor='white',
        height=700,
        showlegend=True,
        legend=dict(x=0.02, y=0.98),
        dragmode='pan'
    )
    
    # Display the chart
    st.plotly_chart(fig, use_container_width=True, config={
        'displayModeBar': True,
        'modeBarButtonsToAdd': ['pan2d', 'zoomIn2d', 'zoomOut2d', 'resetScale2d']
    })
    
    return main_domains, secondary_nodes, process_nodes

def show_detailed_view():
    st.header("Detailed Framework Analysis")
    
    main_domains, secondary_nodes, process_nodes = create_interactive_framework()
    
    # Create tabs for different analysis views
    tab1, tab2, tab3, tab4 = st.tabs(["Domain Analysis", "Connection Matrix", "Implementation Guide", "Export Options"])
    
    with tab1:
        st.subheader("Domain Breakdown")
        
        # Domain statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Main Domains", len(main_domains))
        with col2:
            st.metric("Secondary Nodes", len(secondary_nodes))
        with col3:
            st.metric("Process Nodes", len(process_nodes))
        
        # Domain details table
        domain_data = []
        
        for domain in main_domains.keys():
            secondary_count = sum(1 for node in secondary_nodes.values() if node["parent"] == domain)
            domain_data.append({
                "Domain": domain,
                "Secondary Nodes": secondary_count,
                "Type": "Main",
                "Criticality": "High"
            })
        
        for node, data in secondary_nodes.items():
            domain_data.append({
                "Domain": node,
                "Secondary Nodes": 0,
                "Type": "Secondary",
                "Criticality": "Medium"
            })
        
        df = pd.DataFrame(domain_data)
        st.dataframe(df, use_container_width=True)
    
    with tab2:
        st.subheader("Connection Matrix")
        
        # Create adjacency matrix
        all_nodes = list(main_domains.keys()) + list(secondary_nodes.keys())
        matrix_size = len(all_nodes)
        
        # Initialize matrix
        matrix = np.zeros((matrix_size, matrix_size))
        
        # Fill matrix based on parent-child relationships
        for i, node1 in enumerate(all_nodes):
            for j, node2 in enumerate(all_nodes):
                if node1 in main_domains and node2 in secondary_nodes:
                    if secondary_nodes[node2]["parent"] == node1:
                        matrix[i][j] = 1
                        matrix[j][i] = 1
        
        # Create heatmap
        fig_matrix = go.Figure(data=go.Heatmap(
            z=matrix,
            x=all_nodes,
            y=all_nodes,
            colorscale='Blues',
            showscale=True
        ))
        
        fig_matrix.update_layout(
            title="Domain Connection Matrix",
            xaxis_title="Target Nodes",
            yaxis_title="Source Nodes",
            height=600
        )
        
        st.plotly_chart(fig_matrix, use_container_width=True)
    
    with tab3:
        st.subheader("Implementation Guide")
        
        st.markdown("""
        ### Framework Implementation Steps:
        
        1. **Assess Current State**
           - Map existing security controls to framework nodes
           - Identify gaps in coverage
           - Evaluate connection strengths
        
        2. **Prioritize Implementation**
           - Start with main domains (top level)
           - Focus on high-impact secondary nodes
           - Implement process nodes incrementally
        
        3. **Establish Connections**
           - Define data flows between nodes
           - Implement integration points
           - Monitor connection health
        
        4. **Continuous Improvement**
           - Regular framework reviews
           - Update node relationships
           - Optimize process efficiency
        """)
        
        # Implementation checklist
        st.subheader("Implementation Checklist")
        
        checklist_items = [
            "Identity & Access Management foundation established",
            "Data Security controls implemented",
            "Incident Response procedures defined",
            "Vulnerability Management program active",
            "Risk Management framework operational",
            "Process automation implemented",
            "Integration testing completed",
            "Staff training completed",
            "Documentation updated",
            "Monitoring and metrics established"
        ]
        
        for item in checklist_items:
            st.checkbox(item, key=f"check_{item}")
    
    with tab4:
        st.subheader("Export Options")
        
        # Export current configuration
        if st.button("Generate Framework JSON"):
            framework_export = {
                "main_domains": main_domains,
                "secondary_nodes": secondary_nodes,
                "process_nodes": process_nodes,
                "generated_date": "2024-01-01",
                "version": "1.0"
            }
            
            st.json(framework_export)
            
            # Download button
            json_string = json.dumps(framework_export, indent=2)
            st.download_button(
                label="Download Framework Configuration",
                data=json_string,
                file_name="sabsa_framework.json",
                mime="application/json"
            )
        
        # Export as CSV
        if st.button("Generate CSV Export"):
            export_data = []
            
            for domain, data in main_domains.items():
                export_data.append({
                    "Node": domain,
                    "Type": "Main Domain",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": ""
                })
            
            for node, data in secondary_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Secondary",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": data["parent"]
                })
            
            for node, data in process_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Process",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": ""
                })
            
            export_df = pd.DataFrame(export_data)
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="Download as CSV",
                data=csv,
                file_name="sabsa_framework.csv",
                mime="text/csv"
            )

def main():
    # Navigation
    st.sidebar.title("SABSA Framework")
    view_mode = st.sidebar.radio(
        "Select View",
        ["Interactive Framework", "Detailed Analysis", "About"]
    )
    
    if view_mode == "Interactive Framework":
        create_interactive_framework()
    elif view_mode == "Detailed Analysis":
        show_detailed_view()
    elif view_mode == "About":
        st.header("About SABSA Framework")
        st.markdown("""
        The **Sherwood Applied Business Security Architecture (SABSA)** is a proven methodology 
        for developing business-driven, risk and opportunity focused Security Architecture at both 
        enterprise and solutions levels.
        
        ### Key Features of this Tool:
        - **Interactive Visualization**: Explore the complete SABSA framework structure
        - **Dynamic Connections**: See how different security domains interconnect
        - **Implementation Guidance**: Step-by-step approach to framework adoption
        - **Export Capabilities**: Save configurations for external use
        
        ### Framework Structure:
        - **Main Domains**: 5 primary security domains
        - **Secondary Nodes**: Supporting capabilities and services  
        - **Process Nodes**: Specific processes and controls
        - **Connections**: Relationships and dependencies between elements
        
        This tool replicates the functionality shown in your original SABSA diagram,
        providing an interactive way to explore and implement the framework.
        """)

if __name__ == "__main__":
    main()
