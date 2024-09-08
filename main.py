import asyncio
import ssl

# import socket

# Настройки TLS
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='server.crt', keyfile='server.key')

PORT = 9999


# Асинхронный UDP сервер
class UdpTLSServerProtocol:
    def __init__(self, ctx):
        self.context = ctx

    @staticmethod
    def parse_message(data):
        """
        Разбирает бинарное сообщение на заголовки и тело.
        Формат: заголовки отделяются от тела пустой строкой (\n\n)
        """
        try:
            # Преобразуем бинарные данные в строку для обработки
            data_str = data.decode('utf-8')

            # Разделяем заголовки и тело по первому двойному переносу строки
            headers_part, body_part = data_str.split('\n\n', 1)

            # Разбираем заголовки
            headers = {}
            for header in headers_part.split('\n'):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

            return headers, body_part.encode('utf-8')  # Возвращаем заголовки и тело в виде бинарных данных
        except Exception as e:
            print(f"Ошибка при разборе сообщения: {e}")
            return None, None

    async def handle(self, data, addr, transport):
        # Проверяем, что данные бинарные (тип bytes)
        if not isinstance(data, bytes):
            print(f"Получены не бинарные данные от {addr}, пропуск.")
            return

        print(f"Получены бинарные данные от {addr}")

        # Парсим заголовки и тело
        headers, body = self.parse_message(data)
        if headers is None or body is None:
            print(f"Неверный формат данных от {addr}")
            return

        print(f"Заголовки: {headers}")
        print(f"Тело сообщения: {body}")

        # Создаем SSL объект для обработки данных
        with self.context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_side=True) as tls_conn:
            try:
                # Выполняем TLS рукопожатие
                tls_conn.do_handshake()

                # Передаем данные через TLS (можно наложить логику обработки)
                tls_conn.write(body)  # Отправляем только тело
                encrypted_data = tls_conn.read()

                print(f"Зашифрованные данные: {encrypted_data}")

                # Формируем ответ
                response = b"\x01\x02\x03" + "Сообщение принято".encode('utf-8') + b"\x04\x05\x06"
                transport.sendto(response, addr)
            except ssl.SSLError as e:
                print(f"Ошибка TLS: {e}")

    def connection_made(self, transport):
        self.transport = transport
        print('Сервер запущен')

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle(data, addr, self.transport))


async def main():
    # Создаем UDP сокет
    loop = asyncio.get_running_loop()
    listen = await loop.create_datagram_endpoint(
        lambda: UdpTLSServerProtocol(context),
        local_addr=('0.0.0.0', PORT)
    )

    print(f"Асинхронный UDP TLS сервер слушает порт {PORT}...")
    try:
        await asyncio.sleep(3600)  # Сервер будет работать в течение часа
    finally:
        listen.close()


if __name__ == "__main__":
    asyncio.run(main())
