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
import ply.yacc as yacc

import os
from radl import Feature, RADL, system, network, ansible, configure, contextualize, contextualize_item, \
				 deploy, SoftFeatures, Features, RADLParseException

class RADLParser:

	def __init__(self, autodefinevars = True, **kwargs):
		self.lexer = lex.lex(module=self, debug=0, optimize=0, **kwargs)
		self.yacc = yacc.yacc(module=self, debug=0, optimize=0)

	states = (
	   ('recipe', 'exclusive'),
	   ('body', 'inclusive'),
	)
	
	# Lista de nombres de Token. Esto es obligatorio.
	tokens = (
		'LPAREN',
		'RPAREN',
		'LBRACK',
		'RBRACK',
		'COMMA',
		'NUMBER',
		'AND',
		'EQ',
		'LT',
		'GT',
		'GE',
		'LE',
		'SOFT',
		'STRING',
		'VAR',
		'CONTAINS',
		'DEPLOY',
		'CONFIGURE',
		'SYSTEM',
		'NETWORK',
		'ANSIBLE',
		'RECIPE_LINE',
		'RECIPE_BEGIN',
		'RECIPE_END',
		'CONTEXTUALIZE',
		'STEP',
		'WITH'
	)
	
	# A string containing ignored characters (spaces and tabs)
	t_ignore = ' \t'
	t_recipe_ignore = ''
	t_body_ignore = ' \t'
	
	# Ignore comments.
	def t_comment(self,t):
		r'\#.*'
		pass
	
	def t_body_LE(self,t):
		r'<='
		return t
	
	def t_body_GE(self,t):
		r'>='
		return t
	
	def t_body_EQ(self,t):
		r'='
		return t
	
	def t_body_GT(self,t):
		r'>'
		return t
	
	def t_body_LT(self,t):
		r'<'
		return t
	
	def t_LPAREN(self,t):
		r'\('
		t.lexer.push_state('body')
		return t
	
	def t_RPAREN(self,t):
		r'\)'
		t.lexer.pop_state()
		return t
	
	def t_body_LBRACK(self,t):
		r'\['
		return t
	
	def t_body_RBRACK(self,t):
		r'\]'
		return t
	
	def t_body_COMMA(self,t):
		r'\,'
		return t
	
	def t_newline(self,t):
		r'\n'
		t.lexer.lineno += len(t.value)
	
	def t_body_newline(self,t):
		r'\n'
		t.lexer.lineno += len(t.value)
	
	def t_NUMBER(self,t):
		r'\d+\.?\d*'
		if t.value.find(".") != -1:
			t.value = float(t.value)
		else:
			t.value = int(t.value)
		return t
	
	def t_STRING(self,t):
		r"'([^\\']|\\.)*'"
		#t.value = t.value[1:-1].replace("\\'", "'")
		t.value = t.value[1:-1]
		return t
	
	reserved = {
		'network' : 'NETWORK',
		'ansible' : 'ANSIBLE',
		'system' : 'SYSTEM',
		'soft' : 'SOFT',
		'and' : 'AND',
		'contains' : 'CONTAINS',
		'deploy' : 'DEPLOY',
		'configure': 'CONFIGURE',
		'contextualize': 'CONTEXTUALIZE',
		'step':'STEP',
		'with':'WITH'
	}
	
	def t_VAR(self, t):
		r'[a-zA-Z_.][\w\d_.]*'
		t.type = self.reserved.get(t.value, 'VAR')  # Check reserved words
		return t
	
	def t_RECIPE_BEGIN(self, t):
		r'@begin'
		t.lexer.push_state('recipe')
		return t
	
	def t_recipe_RECIPE_END(self, t):
		r'@end'
		t.lexer.pop_state()
		return t
	
	def t_recipe_RECIPE_LINE(self, t):
		r'.*\n'
		t.type = 'RECIPE_LINE'
		t.lexer.lineno += t.value.count("\n")
		return t
	
	# Error handling rule
	def t_ANY_error(self, t):
		#print "Illegal character '%s'" % t.value[0]
		t.lexer.skip(1)

	def p_radl(self, t):
		"""radl : radl radl_sentence
				| radl_sentence"""
	
		if len(t) == 2:
			t[0] = RADL()
			t[0].add(t[1])
		else:
			t[0] = t[1]
			t[0].add(t[2])
	
	def p_radl_sentence(self, t):
		"""radl_sentence : network_sentence
						 | ansible_sentence
						 | system_sentence
						 | configure_sentence
						 | contextualize_sentence
						 | deploy_sentence"""
		t[0] = t[1]
	
	def p_configure_sentence(self, t):
		"""configure_sentence : CONFIGURE VAR
							  | CONFIGURE VAR LPAREN RECIPE_BEGIN recipe RECIPE_END RPAREN"""
	
		if len(t) == 3:
			t[0] = configure(t[2], reference=True, line=t.lineno(1))
		else:
			t[0] = configure(t[2], t[5], line=t.lineno(1))
	
	def p_recipe(self, t):
		"""recipe : RECIPE_LINE
				  | RECIPE_LINE recipe"""
		if len(t) == 3:
			t[0] = t[1] + t[2]
		else:
			t[0] = t[1]
	
	def p_deploy_sentence(self, t):
		"""deploy_sentence : DEPLOY VAR NUMBER
						   | DEPLOY VAR NUMBER VAR"""
	
		if len(t) == 4:
			t[0] = deploy(t[2], t[3], line=t.lineno(1))
		else:
			t[0] = deploy(t[2], t[3], t[4], line=t.lineno(1))
	
	def p_contextualize_sentence(self, t):
		"""contextualize_sentence : CONTEXTUALIZE LPAREN contextualize_items RPAREN
								  | CONTEXTUALIZE NUMBER LPAREN contextualize_items RPAREN"""
	
		if len(t) == 5:
			t[0] = contextualize(t[3], line=t.lineno(1))
		else:
			t[0] = contextualize(t[4], t[2], line=t.lineno(1))
	
	def p_contextualize_items(self, t):
		"""contextualize_items : contextualize_items contextualize_item 
							   | contextualize_item
							   | empty"""			
		if len(t) == 3:
			t[0] = t[1]
			t[0].append(t[2])
		elif t[1]:
			t[0] = [t[1]]
		else:
			t[0] = []
	
	def p_contextualize_item(self, t):
		"""contextualize_item : SYSTEM VAR CONFIGURE VAR
							  | SYSTEM VAR CONFIGURE VAR STEP NUMBER
							  | SYSTEM VAR CONFIGURE VAR WITH VAR"""
	
		if len(t) == 5:
			t[0] = contextualize_item(t[2], t[4], line=t.lineno(1))
		elif t[5] == "with":
			t[0] = contextualize_item(t[2], t[4], ctxt_tool=t[6], line=t.lineno(1))
		else:
			t[0] = contextualize_item(t[2], t[4], num=t[6], line=t.lineno(1))
	
	def p_network_sentence(self, t):
		"""network_sentence : NETWORK VAR
							| NETWORK VAR LPAREN features RPAREN"""
	
		if len(t) == 3:
			t[0] = network(t[2], reference=True, line=t.lineno(1))
		else:
			t[0] = network(t[2], t[4], line=t.lineno(1))
			
	def p_ansible_sentence(self, t):
		"""ansible_sentence : ANSIBLE VAR LPAREN features RPAREN"""
	
		t[0] = ansible(t[2], t[4], line=t.lineno(1))
	
	def p_system_sentence(self, t):
		"""system_sentence : SYSTEM VAR
						   | SYSTEM VAR LPAREN features RPAREN"""
	
		if len(t) == 3:
			t[0] = system(t[2], reference=True, line=t.lineno(1))
		else:
			t[0] = system(t[2], t[4], line=t.lineno(1))
	
	
	def p_features(self, t):
		"""features : features AND feature
					| feature
					| empty"""
	
		if len(t) == 4:
			t[0] = t[1]
			t[0].append(t[3])
		elif t[1]:
			t[0] = [t[1]]
		else:
			t[0] = []
	
	def p_feature(self, t):
		"""feature : feature_soft
				   | feature_simple
				   | feature_contains"""
	
		t[0] = t[1]
	
	def p_feature_soft(self, t):
		"""feature_soft : SOFT NUMBER LPAREN features RPAREN"""
	
		t[0] = SoftFeatures(t[2], t[4], line=t.lineno(1))
	
	def p_feature_simple(self, t):
		"""feature_simple : VAR comparator NUMBER VAR
						  | VAR comparator NUMBER
						  | VAR comparator LBRACK string_list RBRACK
						  | VAR comparator STRING"""
	
		if len(t) == 6:
			t[0] = Feature(t[1], t[2], t[4], line=t.lineno(1)) 
		elif len(t) == 5:
			t[0] = Feature(t[1], t[2], t[3], unit=t[4],
								 line=t.lineno(1))
		elif len(t) == 4:
			t[0] = Feature(t[1], t[2], t[3], line=t.lineno(1))
	
	def p_empty(self, t):
		"""empty :"""
	
		t[0] = None
	
	def p_comparator(self, t):
		"""comparator : EQ
					  | LT
					  | GT
					  | GE
					  | LE"""
	
		t[0] = t[1]
	
	def p_feature_contains(self, t):
		"""feature_contains : VAR CONTAINS LPAREN features RPAREN"""
	
		t[0] = Feature(t[1], t[2], Features(t[4]), line=t.lineno(1))
		
	def p_string_list(self, t):
		"""string_list : string_list COMMA STRING
					   | STRING
					   | empty"""

		if len(t) == 4:
			t[0] = t[1]
			t[0].append(t[3])
		elif t[1]:
			t[0] = [t[1]]
		else:
			t[0] = []
	
	def p_error(self, t):
		raise RADLParseException("Parse error in: " + str(t), line=t.lineno if t else None)
	
	def parse(self, data):
		self.lexer.lineno = 1
		self.lexer.begin('INITIAL')
		return self.yacc.parse(data, tracking=True, debug=0, lexer=self.lexer)
	
def parse_radl(data):
	"""
	Parse a RADL document.

	Args:
	- data(str): filepath to a RADL content or a string with content.

	Return: RADL object.
	"""

	if data is None:
		return None
	elif os.path.isfile(data):
		f = open(data)
		data = "".join(f.readlines())
		f.close()
	elif data.strip() == "":
		return RADL()
	data = data + "\n"

	parser = RADLParser(lextab = 'radl')
	return parser.parse(data)