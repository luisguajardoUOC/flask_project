from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from flask import Blueprint, jsonify
import mysql.connector
from db import get_db_connection
from db_queries import DatabaseQueries
import logging

history_bp = Blueprint('history', __name__)
db_queries = DatabaseQueries()

@history_bp.route('/history', methods=['GET'])
def history_six_months():
    #cursor = self.db_connection.cursor(dictionary=True)
    # Calcular el rango de fechas para los últimos 6 meses
    #end_date = datetime.now()
    # start_date = end_date - timedelta(days=6*30)
    #start_date = end_date - relativedelta(months=6)
    # Ajustar end_date al último día del mes actual
    end_date = datetime.now().replace(day=31, hour=23, minute=59, second=59, microsecond=999999)

    # Calcular start_date como 6 meses antes
    start_date = end_date - relativedelta(months=6)
    logging.info(start_date)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    history = []
    try:
        results = db_queries.getHistorical(start_date, end_date)
        # Agregar la regla a la lista
        for row in results:
            history.append({
                "id": row['id'],
                "user_id": row['user_id'],
                "url": row['url'],
                "action": row['action'],
                "user_rol": row['user_rol'],
                "userIP": row['userIP'],
                "timestamp": row['timestamp'],
                "type": row['type']
            })
        return jsonify(history), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@history_bp.route('/history/<int:month>', methods=['GET'])
def history_for_month(month):
    # Aquí filtras por el mes específico
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    history = []

    try:
        results = db_queries.getHistoricalForMonth(month)
        for row in results:
            history.append({
                "id": row['id'],
                "user_id": row['user_id'],
                "url": row['url'],
                "action": row['action'],
                "user_rol": row['user_rol'],
                "userIP": row['userIP'],
                "timestamp": row['timestamp'],
                "type": row['type']
            })
        return jsonify(history), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()