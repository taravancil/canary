# -*- coding: utf-8 -*-
from celery import Celery

import canary.config
from canary.db import db_session

celery = Celery('tasks')
celery.config_from_object('canary.config.Celery')

class SqlAlchemyTask(celery.Task):
    abstract = True

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        db_session.remove()

