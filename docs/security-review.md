# Разбор результатов SAST

SpotBugs 4.10.4.1 + Find Security Bugs 1.14.0 проверяет всю категорию SECURITY
при threshold Low и effort Max. Проверка не отключена; исключения ниже узкие
и перечислены в `config/spotbugs-reviewed.xml`.

| Находка первого прогона | Решение |
| --- | --- |
| `XSS_SERVLET` в `Errors.write` | Удалена ручная конкатенация JSON. Ответ сериализуется Jackson в байты и выдаётся как `application/json` с `nosniff`. Исключение для XSS не добавлялось. |
| `SPRING_ENDPOINT`, три метода `ApiController` | Информационная отметка поверхности атаки. Методы проверены интеграционными тестами; доступ регулирует SecurityFilterChain. Исключён только этот тип для этого класса. |
| `SPRING_CSRF_PROTECTION_DISABLED` в `SecurityConfig` | Принято для stateless API: JWT передаётся явно в Authorization; приложение не использует cookie, form login или Basic Auth. Браузер не добавляет Bearer автоматически. Cross-origin CORS не разрешён. Исключён только этот тип для этого класса. При добавлении cookie-аутентификации решение нужно пересмотреть и включить CSRF-защиту. |

Проверки подтверждают отсутствие сессионной cookie, отказ без JWT,
отказ для JWT в query string, неправильной подписи, срока действия, issuer и audience,
экранирование HTML и изоляцию данных владельцев.

Источники:

- [Spring Security: CSRF и stateless browser applications](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html).
- [Find Security Bugs: описания правил](https://find-sec-bugs.github.io/bugs.htm).
- [Spring Security: JWT Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html).

Дополнительно версия embedded Tomcat повышена с управляемой Spring Boot 4.1.1
версии 11.0.24 до 11.0.25. Последняя содержит исправления, в том числе
CVE-2026-68763 (DoS в HTTP/2) и CVE-2026-65182 (обход security constraints).
Источник: [официальный бюллетень Apache Tomcat](https://tomcat.apache.org/security-11.html).
Это обновление зависимости, а не подавление CVE в отчёте SCA.

Учебные ограничения: нет регистрации, refresh-токенов, немедленного отзыва JWT и
распределённого rate limiting. Токен действует 15 минут; лимитер хранится в памяти
одного процесса, окно — календарная минута. Для публикации вне localhost нужен HTTPS
на доверенном reverse proxy, отдельная runtime-роль PostgreSQL без DDL и управление
секретами. Наличие сканеров не является доказательством отсутствия всех уязвимостей.
