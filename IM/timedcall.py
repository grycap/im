#!/usr/bin/python
# coding: utf-8
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

import time
import uuid


class Timer(object):
    """
    Este es una especie de temporizador, que permite definir un tiempo maximo de
    ejecucion de "tareas" y comprueba si daria tiempo a ejecutar mas cosas en funcion
    de lo que se haya ejecutado antes.

    > vamos, se debe utilizar para intentar no pasarnos de cosas a ejecutar en un
      tiempo determinado

      ej: t = Timer(10)
          while True:
            if not t.can_call:
                break
            ejecutar_cosas()
            ...
    """

    def __init__(self, timer=1):
        self._timer = timer
        self._start_time = time.time()
        self._last_duration = 0
        self._elapsed = 0
        self._max_time = self._start_time + self._timer
        self._max_duration = 0

    def start(self, timer=None):
        if timer is not None:
            self._timer = timer
        self._start_time = time.time()
        self._max_time = self._start_time + self._timer
        self._elapsed = self._start_time
        self._last_duration = 0
        self._max_duration = 0

    def can_call(self):
        cur_time = time.time()
        elapsed = cur_time - self._elapsed  # el tiempo que ha pasado desde la ultima
        if elapsed > self._max_duration:
            self._max_duration = elapsed
        can_call = (cur_time + self._max_duration) < self._max_time
        self._elapsed = cur_time
        return can_call

    def __str__(self):
        return "timer: %f, last call: %f, last duration: %f" % (self._timer, self._elapsed, self._last_duration)


class TimedCall(object):
    """
    Esta clase permite hacer llamadas a callbacks cada cierto tiempo. En contra de
    lo que pueda parecer, no es autonoma y no genera un nuevo thread. En su lugar,
    lo que hace es que se espera a que se haga la llamada y, si tocara porque hubiera
    pasado mas tiempo del que debia esperar, entonces haria la llamada efectiva.

    La forma de proceder seria haciendo
        call = TimedCall(callback)
        while (True):
            call.call
            sleep(1)
    """

    def __init__(self, callback, args=[], time_between_calls=5, retry_missed=False):
        self._next_call = time.time()
        self._time_between_calls = time_between_calls
        self._retry_missed = retry_missed
        self._callback = callback
        self._args = args
        self._id = uuid.uuid4()

    @property
    def id(self):
        return self._id

    @property
    def programmed_time(self):
        return self._next_call

    @property
    def time_to_next_call(self):
        ttn = self._next_call - time.time()
        if ttn < 0:
            return 0
        return ttn

    def call(self, time_between_calls=None, callback=None, args=[]):
        """
        Esta funcion comprueba si "toca" hacer la llamada y en caso de que asi sea,
        la hace. Permite hecer overriding del tiempo entre llamadas y de la llamada
        en si
        """
        if time_between_calls is None:
            time_between_calls = self._time_between_calls

        if callback is None:
            callback = self._callback
            args = self._args

        cur_time = time.time()
        elapsed_time = self._next_call - cur_time

        if elapsed_time < 0:
            retval = None
            if callback is not None:
                retval = callback(*args)
            self._next_call = cur_time + time_between_calls
            if not self._retry_missed:
                self._next_call = cur_time + \
                    ((self._next_call - time.time()) % time_between_calls)
            return True, retval
        else:
            return False, None

    def reprogram(self, elapsed_time=0):
        self._next_call = self._next_call + elapsed_time

# TODO: hacer un gestor de "timed calls" en el que se puedan crear calls y que
# genere un thread en el que se encargue de hacer las llamadas.
# El sleep se haria del periodo de tiempo menor
