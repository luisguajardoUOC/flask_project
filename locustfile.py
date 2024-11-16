from locust import User, task, between
import requests
import time

class ProxyUser(User):
    wait_time = between(1, 5)

    @task
    def access_blocked_page(self):
        proxies = {"https": "http://localhost:8080", "http": "http://localhost:8080"}
        start_time = time.time()
        try:
            response = requests.get(
                "https://www.netflix.com",
                headers={"User-Agent": "LocustTestClient"},
                proxies=proxies,
                verify=False  # Desactiva verificación SSL para mitmproxy
            )
            total_time = int((time.time() - start_time) * 1000)  # Tiempo en ms
            if response.status_code == 403:
                print("Access blocked as expected.")
                # Registrar como éxito en Locust
                self.environment.events.request.fire(
                    request_type="GET",
                    name="Access Netflix (Blocked)",
                    response_time=total_time,
                    response_length=len(response.content),
                    context=None,
                    exception=None
                )
            else:
                print(f"Unexpected status code: {response.status_code}")
                # Registrar como error en Locust
                self.environment.events.request.fire(
                    request_type="GET",
                    name="Access Netflix (Unexpected)",
                    response_time=total_time,
                    response_length=0,
                    context=None,
                    exception=f"Unexpected status code: {response.status_code}"
                )
        except requests.exceptions.RequestException as e:
            total_time = int((time.time() - start_time) * 1000)
            print(f"Request failed: {e}")
            # Registrar como fallo en Locust
            self.environment.events.request.fire(
                request_type="GET",
                name="Access Netflix (Failed)",
                response_time=total_time,
                response_length=0,
                context=None,
                exception=e
            )
