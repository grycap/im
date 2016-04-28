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
import sys
from Queue import Queue, Empty
import threading
from SimpleXMLRPCServer import SimpleXMLRPCServer
import SocketServer
import time
from timedcall import TimedCall
from config import Config


class RequestQueue(Queue):
    """
    Modela una cola del sistema que procesa las peticiones encoladas de acuerdo a unas prioridades.
    Se elige la prioridad con indice menor, siguiendo la prioridad convencional de las PriorityQueue
    estandar.
    """

    def process_requests(self, max_requests, wait_time_for_element=0):
        """
        Procesa solicitudes de la cola, utilizando el metodo "process" de la clase
        Request.
        * Como mucho procesa "max_requests" solicitudes (si max_requests <= 0, procesa
          todas las solicitudes de la cola

        Devuelve el numero de solicitudes procesadas
        """

        # Al trabajar de esta forma, estamos secuencializando la ejecucion de las peticiones
        # sin embargo, al localizar esto aqui podriamos, potencialmente, considerar el tratar
        # las peticiones en threads. Sin embargo, eso podria aumentar considerablemente la
        # complejidad del sistema
        requests_processed = 0
        empty = False
        while (max_requests <= 0 or requests_processed < max_requests) and not empty:
            try:
                if wait_time_for_element > 0:
                    _, request = self.get(True, wait_time_for_element)
                else:
                    _, request = self.get(False)
                request.process()
                requests_processed = requests_processed + 1
            except Empty:
                empty = True
                pass
        return requests_processed

    def generic_process_loop(self, callback=None, timeout=0.5, max_requests=-1):
        """
        Implementa un bucle de mensajes clasico, despachando las solicitudes de la propia cola.
        Permite la llamada a un callback, cada vez que se realiza un bloque de procesamiento de
        solicitudes, de forma que, por ejemplo, se pueda actualizar el estado del sistema o
        realizar acciones similares

        La funcion termina al pulsar Ctrl-C, capturando la señal para que no de un error feo
        """
        try:
            while True:
                self.process_requests(max_requests)
                if callback is not None:
                    callback()
                time.sleep(timeout)
        except KeyboardInterrupt:
            # La idea es capturar el Ctrl-C para que acabe de una forma
            # "normal"

            pass

    def timed_process_loop(self, callback=None, time_between_callbacks=3,
                           retry_missing_calls=False, exit_callback=None):
        """
        Implementa un bucle de mensajes que trata de ejecutar un callback de acuerdo a una
        frecuencia temporal.

        La diferencia con la anterior es que generic_process_loop ejecuta por rafagas y luego espera
        un tiempo, con lo que la ejecucion del callback no tiene en cuenta el tiempo que ha tardado
        en ejecutarse las peticiones, mientras que en esta si se trata de tener en cuenta, para
        hacer enfasis en la frecuencia de ejecucion de la llamada.

        La funcion termina al pulsar Ctrl-C, capturando la señal para que no de un error feo
        """
        try:
            tcall = TimedCall(
                callback, [], time_between_callbacks, retry_missing_calls)
            while True:
                tcall.call()
                self.process_requests(1, tcall.programmed_time - time.time())
        except KeyboardInterrupt:
            # La idea es capturar el Ctrl-C para que acabe de una forma
            # "normal"
            if exit_callback:
                exit_callback()
            sys.exit(0)


def get_system_queue():
    """
    Obtiene la cola general del sistema. Al utilizar este mecanismo, diferimos la creacion
    de la cola hasta el momento en que sea necesario y nos evitamos la utilizacion de variables
    globales.
    """
    global SYSTEM_REQUESTS_QUEUE
    try:
        SYSTEM_REQUESTS_QUEUE
    except:
        SYSTEM_REQUESTS_QUEUE = RequestQueue()
    return SYSTEM_REQUESTS_QUEUE


class Request(object):
    """
    Clase generica para modelar las peticiones que se van a hacer al sistema. Al crear la peticion, esta se
    encola directamente en el sistema, en el constructor de la clase.

    Para crear una nueva Request especifica basta con sobreescribir el constructor (y llamar al de esta clase,
    para implementar la funcionalidad y la semantica correcta; aqui se puede variar la prioridad de la peticion),
    y sobreescribir el metodo _execute, que es el que en realidad implementa la funcionalidad.
    """

    STATUS_PENDING = 0  # La peticion esta pendiente de ser ejecutada
    STATUS_PROCESSING = 1  # La peticion esta siendo procesada
    STATUS_PROCESSED = 2  # La peticion ha sido procesada
    STATUS_ERROR = 3  # Ha ocurrido un error al procesar la peticion

    PRIORITY_HIGH = 0  # Prioridad alta
    PRIORITY_NORMAL = 1  # Prioridad normal
    PRIORITY_LOW = 2  # Prioridad baja

    def __init__(self, arguments=(), priority=PRIORITY_NORMAL):
        """
        La prioridad debe utilizarse principalmente para temas de interaccion con el usuario. Por ejemplo
        consultar el estado del sistema deberia ser prioritario puesto que en realidad no necesita realizar
        procesamiento y resultaria raro que el usuario necesitase esperar demasiado rato
        """
        self.__event = threading.Event()
        self.__value = None
        self.__status = Request.STATUS_PENDING
        self.__arguments = arguments

        # Este semaforo es para acceder a los atributos y que sea "threadsafe"
        self.__semaphore = threading.Lock()

        # Se encola en la cola general del sistema
        get_system_queue().put((priority, self))

    @property
    def arguments(self):
        """
        Devuelve la lista de argumentos que han sido enviados en el constructor de la clase. Estos argumentos
        no se pueden modificar en origen, para mantener la integridad de la funcion
        """
        return self.__arguments

    def wait(self):
        """
        Espera a que se reciba la señal de fin de procesamiento de la peticion
        """
        self.__event.wait()

    def set(self, x=True):
        """
        Establece el resultado del procesamiento de la peticion
        """
        self.__semaphore.acquire()
        self.__value = x
        self.__semaphore.release()

    def get(self):
        """
        Obtiene el resultado de la peticion
        """
        self.__semaphore.acquire()
        value = self.__value
        self.__semaphore.release()
        return value

    def status(self):
        """
        Obtiene el estado de procesamiento de la peticion
        """
        self.__semaphore.acquire()
        status = self.__status
        self.__semaphore.release()
        return status

    def set_status(self, status):
        """
        Modifica el estado de procesamiento de la peticion
        """
        self.__semaphore.acquire()
        self.__status = status
        self.__semaphore.release()

    def process(self):
        """
        Coordina el procesamiento de la peticion
        """
        self.set_status(Request.STATUS_PROCESSING)

        result = self._execute()

        if result:
            self.set_status(Request.STATUS_PROCESSED)
        else:
            self.set_status(Request.STATUS_ERROR)

        # Se ha terminado de ejecutar, asi que notificamos
        self.__event.set()

    def _execute(self):
        """
        Implementa de forma efectiva el procesamiento de la ejecucion
        * Este es el metodo que se ha de sobrescribir para crear nuestrar propias peticiones
        """
        return True


class AsyncRequest(Request):
    """
    Esta clase, que desciende de Request, es un tipo especial de peticiones que hace que se ejecuten
    de forma asincrona, en un thread independiente
    """

    def __init__(self, arguments=(), priority=Request.PRIORITY_NORMAL):
        Request.__init__(self, arguments, priority)
        self.__thread = None

    def process(self):
        """
        En este caso lo que se hace es lanzar el thread
        """
        self.__thread = threading.Thread(target=Request.process, args=[self])
        self.__thread.start()


class AsyncXMLRPCServer(SocketServer.ThreadingMixIn, SimpleXMLRPCServer):

    def serve_forever_in_thread(self):
        """
        Hace que el servidor se inicie en un thread, para que se pueda trabajar de forma desacoplada
        con el. De esta forma, por ejemplo, se habilita que la cola del sistema este en un thread
        independiente del servidor y que asi no se bloqueen entre ellos.
        """
        self.__thread = threading.Thread(target=self.serve_forever)

        # Utilizamos el mecanismo del "daemon" para hacer que este thread se muera solo (cuando no
        # quedan "main threads" vivos)
        self.__thread.daemon = True
        self.__thread.start()

if Config.XMLRCP_SSL:
    from springpython.remoting.xmlrpc import SSLServer

    class AsyncSSLXMLRPCServer(SocketServer.ThreadingMixIn, SSLServer):

        def __init__(self, *args, **kwargs):
            super(AsyncSSLXMLRPCServer, self).__init__(*args, **kwargs)

        def serve_forever_in_thread(self):
            """
            Hace que el servidor se inicie en un thread, para que se pueda trabajar de forma desacoplada
            con el. De esta forma, por ejemplo, se habilita que la cola del sistema este en un thread
            independiente del servidor y que asi no se bloqueen entre ellos.
            """
            self.__thread = threading.Thread(target=self.serve_forever)

            # Utilizamos el mecanismo del "daemon" para hacer que este thread se muera solo (cuando no
            # quedan "main threads" vivos)
            self.__thread.daemon = True
            self.__thread.start()

        def register_functions(self):
            pass
