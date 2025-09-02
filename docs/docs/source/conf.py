import os
import sys
sys.path.insert(0, os.path.abspath('../..'))  # Add the project root directory to the Python path

import settings

project = 'NGFW from Policy to Code'
copyright = '2025, Nikolay Matveev; Companion book copyright 2025, Packt Publishing Ltd. - All Rights Reserved.'
version = settings.POLICY_VERSION
release = settings.POLICY_VERSION
author = 'Nikolay Matveev'

html_show_sourcelink = False

html_theme_options = {
   "logo": {
      "image_light": "_static/book-cover.png",
      "image_dark": "_static/book-cover.png",
      "link": "https://www.packtpub.com/en-gb/product/palo-alto-networks-from-policy-to-code-9781835881293",
      "alt_text": "This project has a companion book published by Packt Publishing in August, 2025. Click here for more details (opens in the same window).",
   }
}

html_additional_pages = {
    'index': 'redirect.html'
}

html_theme = 'sphinx_book_theme'
html_static_path = ['_static']
html_js_files = ["open-external-links.js"]
html_css_files = ["external-links.css", "navigation-fix.css"]

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx_plotly_directive',
    'sphinx.ext.graphviz'
]

graphviz_output_format = 'svg'

# Configuration for sphinx-plotly-directive
plotly_html_show_source_link = False
plotly_html_show_formats = False

templates_path = ['_templates']
exclude_patterns = []

source_suffix = '.rst'
master_doc = 'index'
