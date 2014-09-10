# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import ply.lex as lex

# Ponemos los estados para gestionan el tema de las recetas
states = (
   ('recipe', 'exclusive'),
)

# Lista de nombres de Token. Esto es obligatorio.
tokens = (
	'LPAREN',
	'RPAREN',
	'NUMBER',
	'AND',
	'OR',
	'EQ',
	'LT',
	'GT',
	'GE',
	'LE',
	'NETWORK',
	'SYSTEM',
	'SOFT',
	'STRING',
	'VAR',
	'CONTAINS',
	'DEPLOY',
	'CONFIGURE',
	'RECIPE_LINE',
	'RECIPE_BEGIN',
	'RECIPE_END',
	'CONTEXTUALIZE',
	'STEP'
)

# A string containing ignored characters (spaces and tabs)
t_ignore = ' \t\r'

t_recipe_ignore = ''

# Ignore comments.
def t_comment(t):
	r'\#.*'
	pass

def t_LE(t):
	r'<='
	return t

def t_GE(t):
	r'>='
	return t

def t_EQ(t):
	r'='
	return t

def t_GT(t):
	r'>'
	return t

def t_LT(t):
	r'<'
	return t

def t_LPAREN(t):
	r'\('
	return t

def t_RPAREN(t):
	r'\)'
	return t

def t_ANY_newline(t):
	r'\n+'
	t.lexer.lineno += len(t.value)

def t_NUMBER(t):
	r'\d+\.?\d*'
	if t.value.find(".") != -1:
		t.value = float(t.value)
	else:
		t.value = int(t.value)
	return t

def t_STRING(t):
	r"'([^\\']+|\\'|\\\\)*'"  # I think this is right ...
	t.value = t.value[1:-1].decode("string-escape")  # .swapcase() # for fun
	return t

reserved = {
	'network' : 'NETWORK',
	'system' : 'SYSTEM',
	'soft' : 'SOFT',
	'and' : 'AND',
	'or' : 'OR',
	'contains' : 'CONTAINS',
	'deploy' : 'DEPLOY',
	'configure': 'CONFIGURE',
	'contextualize': 'CONTEXTUALIZE',
	'step':'STEP'
}

def t_VAR(t):
	r'[a-zA-Z_.][\w\d_.]*'
	t.type = reserved.get(t.value, 'VAR')  # Verificar palabras reservadas
	return t

def t_RECIPE_BEGIN(t):
	r'@begin'
	t.lexer.begin('recipe')
	return t

def t_recipe_RECIPE_END(t):
	r'@end'
	t.lexer.begin('INITIAL')
	return t

# Definimos la receta con cualquier caracter diferente de "(" y ")"
def t_recipe_RECIPE_LINE(t):
	r'.+'
	t.type = 'RECIPE_LINE'
	return t

# Error handling rule
def t_ANY_error(t):
	print "Illegal character '%s'" % t.value[0]
	t.lexer.skip(1)

#lexer = lex.lex(optimize=1)
lexer = lex.lex()
if __name__ == "__main__":
	lex.runmain(lexer)
