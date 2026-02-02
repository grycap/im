# General information about the project.
project = 'IM Documentation'
copyright = '2025, I3M-GRyCAP'
author = 'micafer'

version = '1.19'
release = '1.19.2'

master_doc = 'index'

# -- General configuration

extensions = [
#    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.mathjax',
    'sphinx.ext.viewcode',
    'sphinx.ext.graphviz',
    'sphinx_toolbox.confval'
]

intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}
intersphinx_disabled_domains = ['std']

templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'
html_logo = "images/logoim.png"
html_theme_options = {"style_nav_header_background": "black"}

# -- Options for EPUB output
epub_show_urls = 'footnote'
