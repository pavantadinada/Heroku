import plotly
import plotly.graph_objects as go
import dash
import dash_core_components as dcc
import dash_html_components as html
import pandas as pd




df = pd.read_csv('death.csv')

#app = dash.Dash(__name__, external_stylesheets=["https://codepen.io/chriddyp/pen/bWLwgP.css"])
#server = app.server

fig = go.Figure(data=go.Choropleth(
    locations = df['CODE'],
    z = df['DEATHS (THOUSANDS)'],
    text = df['COUNTRY'],
    colorscale = 'Blues',
    autocolorscale=False,
    reversescale=True,
    marker_line_color='darkgray',
    marker_line_width=0.5,
    colorbar_tickprefix = '',
    colorbar_title = 'DEATHS<br>THOUSANDS',
))

fig.update_layout(
    title_text='WORLD HEART FAILURE DEATHS',
    geo=dict(
        showframe=False,
        showcoastlines=False,
        projection_type='equirectangular'
    ),
    annotations = [dict(
        x=0.5,
        y=0.1,
        xref='paper',
        yref='paper',
        text='Deaths in Thousands',
        showarrow = False
    )]
)

external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
server = app.server




app.layout = html.Div([
    dcc.Graph(figure=fig)
])




if __name__ == "__main__":
    app.run_server(debug=True)
