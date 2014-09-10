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

import os
import ply.yacc as yacc
from radl_lex import *
from radl import Feature, RADL, system, network, configure, contextualize, contextualize_item, \
				 deploy, SoftFeatures, Features, RADLParseException

#tokens = radl_lex.tokens

def p_radl(t):
	"""radl : radl radl_sentence
			| radl_sentence"""

	if len(t) == 2:
		t[0] = RADL()
		t[0].add(t[1])
	else:
		t[0] = t[1]
		t[0].add(t[2])

def p_radl_sentence(t):
	"""radl_sentence : network_sentence
					 | system_sentence
					 | configure_sentence
					 | contextualize_sentence
					 | deploy_sentence"""
	t[0] = t[1]

def p_configure_sentence(t):
	"""configure_sentence : CONFIGURE VAR
						  | CONFIGURE VAR LPAREN RECIPE_BEGIN recipe RECIPE_END RPAREN"""

	if len(t) == 3:
		t[0] = configure(t[2], reference=True, line=t.lineno(1))
	else:
		t[0] = configure(t[2], t[5], line=t.lineno(1))

def p_recipe(t):
	"""recipe : RECIPE_LINE
			  | RECIPE_LINE recipe"""
	if len(t) == 3:
		t[0] = t[1] + "\n" + t[2]
	else:
		t[0] = t[1]

def p_deploy_sentence(t):
	"""deploy_sentence : DEPLOY VAR NUMBER
					   | DEPLOY VAR NUMBER VAR"""

	if len(t) == 4:
		t[0] = deploy(t[2], t[3], line=t.lineno(1))
	else:
		t[0] = deploy(t[2], t[3], t[4], line=t.lineno(1))

def p_contextualize_sentence(t):
	"""contextualize_sentence : CONTEXTUALIZE LPAREN contextualize_items RPAREN
							  | CONTEXTUALIZE NUMBER  LPAREN contextualize_items RPAREN"""

	if len(t) == 5:
		t[0] = contextualize(t[3], line=t.lineno(1))
	else:
		t[0] = contextualize(t[4], t[2], line=t.lineno(1))

def p_contextualize_items(t):
	"""contextualize_items : contextualize_items contextualize_item 
						   | contextualize_item"""

	if len(t) == 2:
		t[0] = [t[1]]
	else:
		t[0] = t[1]
		t[0].append(t[2])

def p_contextualize_item(t):
	"""contextualize_item : SYSTEM VAR CONFIGURE VAR
						  | SYSTEM VAR CONFIGURE VAR STEP NUMBER"""

	if len(t) == 5:
		t[0] = contextualize_item(t[2], t[4], line=t.lineno(1))
	else:
		t[0] = contextualize_item(t[2], t[4], t[6], line=t.lineno(1))

def p_network_sentence(t):
	"""network_sentence : NETWORK VAR
						| NETWORK VAR LPAREN features RPAREN"""

	if len(t) == 3:
		t[0] = network(t[2], reference=True, line=t.lineno(1))
	else:
		t[0] = network(t[2], t[4], line=t.lineno(1))

def p_system_sentence(t):
	"""system_sentence : SYSTEM VAR
					   | SYSTEM VAR LPAREN features RPAREN"""

	if len(t) == 3:
		t[0] = system(t[2], reference=True, line=t.lineno(1))
	else:
		t[0] = system(t[2], t[4], line=t.lineno(1))


def p_features(t):
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

def p_feature(t):
	"""feature : feature_soft
			   | feature_simple
			   | feature_contains"""

	t[0] = t[1]

def p_feature_soft(t):
	"""feature_soft : SOFT NUMBER LPAREN features RPAREN"""

	t[0] = SoftFeatures(t[2], t[4], line=t.lineno(1))

def p_feature_simple(t):
	"""feature_simple : VAR comparator NUMBER VAR
					  | VAR comparator NUMBER
					  | VAR comparator STRING"""

	if len(t) == 5:
		t[0] = Feature(t[1], t[2], t[3], unit=t[4],
							 line=t.lineno(1))
	elif len(t) == 4:
		t[0] = Feature(t[1], t[2], t[3], line=t.lineno(1))

def p_empty(t):
	"""empty :"""

	t[0] = None

def p_comparator(t):
	"""comparator : EQ
				  | LT
				  | GT
				  | GE
				  | LE"""

	t[0] = t[1]

def p_feature_contains(t):
	"""feature_contains : VAR CONTAINS LPAREN features RPAREN"""

	t[0] = Feature(t[1], t[2], Features(t[4]), line=t.lineno(1))

def p_error(t):
	raise RADLParseException("Parse error in: " + str(t))

def parse_radl(data):
	"""
	Parse a RADL document.

	Args:
	- data(str): filepath to a RADL content or a string with content.

	Return: RADL object.
	"""

	if os.path.isfile(data):
		f = open(data)
		data = "".join(f.readlines())
		f.close()
	elif data == "":
		return RADL()
	lexer.lineno = 1
	return yacc.yacc().parse(data)
