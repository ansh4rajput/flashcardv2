from werkzeug.exceptions import HTTPException
from sqlalchemy import exc
from flask import make_response,render_template
import json

from werkzeug.wrappers import response

class No_cards_error(HTTPException):
    def __init__(self,status_code):
        data = { "Error!!!": " No cards in Response Body "}
        self.response = make_response(json.dumps(data),status_code)


class Invalid_error(HTTPException):
    def __init__(self,message,status_code):
        data = {  "Error!!!":  message + " does not Exist" }
        self.response = make_response(json.dumps(data),status_code)






