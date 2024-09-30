import mysql.connector

conexion = mysql.connector.connect(
  host="localhost",
  user="root",
  password="lardin718"
)

print(conexion)



cursor=conexion.cursor()
cursor.execute("show databases")
for base in cursor:
    print(base)
conexion.close()