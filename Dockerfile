# Usa la imagen base de Python
FROM python:3.12-slim

# Actualiza e instala dependencias del sistema necesarias para algunas bibliotecas
RUN apt update && apt install -y gcc libffi-dev libssl-dev python3-dev build-essential curl

# Establece el directorio de trabajo
WORKDIR /app

# Copia el archivo de dependencias
COPY requirements.txt requirements.txt


# Copia los archivos del proyecto al contenedor
COPY . /app
COPY .env /app/.env

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Exponer puerto para Flask
EXPOSE 5000 8080


# Comando para ejecutar la aplicación
CMD ["flask", "run", "--host=0.0.0.0"]
