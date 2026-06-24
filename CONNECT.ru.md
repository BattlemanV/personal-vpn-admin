# FamilyNet — подключение

## 3 ступени защиты

| Ступень | Порт | Протокол | Клиенты |
|---|---|---|---|
| **1. WireGuard** | 51820/udp | WG | Любой WG-клиент |
| **2. AmneziaWG** | 31121/udp | AWG (обфускация) | AmneziaVPN |
| **3. Xray** | 443/tcp | **REALITY** | Windows/Android: v2rayNG, Nekoray, V2Box |
| | 8445/tcp | **XHTTP** | iOS: Hiddify |
| | 8444/tcp | **WS** | iOS: AmneziaVPN, Hiddify |

## Где взять ссылки

1. Зайдите в веб-панель FamilyNet (http://147.45.169.35:8082)
2. Введите пароль администратора
3. Откройте любое устройство
4. Для Xray — нажмите REALITY, XHTTP или WS:

   - **REALITY** — самый защищённый, для Windows/Android/macOS. Работает через порт 443, маскируется под HTTPS.
   - **XHTTP** — для iOS (Hiddify). Работает через порт 8445 без TLS.
   - **WS** — универсальный fallback для iOS (AmneziaVPN, Hiddify). Порт 8444.

## Рекомендации по клиентам

### iOS — AmneziaVPN (рекомендуется)
Поддерживает WG, AWG и Xray (WS). Одно приложение для всех трёх ступеней.

### iOS — Hiddify
Поддерживает XHTTP (работает), WS (работает). REALITY на iOS сломан (баг Hiddify v4).

### Windows/Android — любой клиент
REALITY работает на всех платформах, кроме iOS. Используйте v2rayNG, Nekoray, V2Box и т.д.

## WireGuard (1-я ступень)
Конфиг скачивается из панели — кнопка "Config" или QR.

## AmneziaWG (2-я ступень)
Конфиг с обфускацией (Jc=4, Jmin=10, Jmax=50, S1=97, S2=99).
При открытии в AmneziaVPN автоматически импортируется с правильными параметрами.
