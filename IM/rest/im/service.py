import datetime
import flask
import logging
from IM.config import Config
from IM.InfrastructureManager import InfrastructureManager
from IM import get_ex_error
from IM.rest.utils import return_error, get_auth_header, format_output, require_auth


sys_bp = flask.Blueprint("service", __name__, url_prefix='/')
logger = logging.getLogger('InfrastructureManager')


@sys_bp.route('/stats', methods=['GET'])
@require_auth
def RESTGetStats(auth=None):
    try:
        init_date = None
        if "init_date" in flask.request.args.keys():
            init_date = flask.request.args.get("init_date").lower()
            init_date = init_date.replace("/", "-")
            parts = init_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                return return_error(400, "Incorrect format in init_date parameter: YYYY/MM/dd")
        else:
            init_date = "1970-01-01"

        end_date = None
        if "end_date" in flask.request.args.keys():
            end_date = flask.request.args.get("end_date").lower()
            end_date = end_date.replace("/", "-")
            parts = end_date.split("-")
            try:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                datetime.date(year, month, day)
            except Exception:
                return return_error(400, "Incorrect format in end_date parameter: YYYY/MM/dd")

        stats = InfrastructureManager.GetStats(init_date, end_date, auth)
        return format_output(stats, default_type="application/json", field_name="stats")
    except Exception as ex:
        logger.exception("Error getting stats")
        return return_error(400, "Error getting stats: %s" % get_ex_error(ex))


@sys_bp.route('/static/<filename>', methods=['GET'])
def static_files(filename):
    if Config.STATIC_FILES_DIR:
        return flask.send_from_directory(Config.STATIC_FILES_DIR, filename)
    else:
        return return_error(404, "Static files not enabled.")


@sys_bp.route('/version')
def RESTGetVersion():
    try:
        from IM import __version__ as version
        return format_output(version, field_name="version")
    except Exception as ex:
        return return_error(400, "Error getting IM version: %s" % get_ex_error(ex))
