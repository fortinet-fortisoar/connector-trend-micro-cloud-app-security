""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
logger = get_logger('trend-micro-cloud-app-security')


class TrendMicroCloudAppSecurity(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            if not operation:
                logger.error('Unsupported operation: {}'.format(operation))
                raise ConnectorError('Unsupported operation')
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config=None):
        try:
            return _check_health(config)
        except Exception as err:
            raise ConnectorError(err)


