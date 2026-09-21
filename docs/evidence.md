# Подтверждение проверок для сдачи

Отчёты и скриншоты должны относиться к реальному запуску, а не к предполагаемому результату.
Локальные проверки не заменяют требуемый заданием запуск GitHub Actions.

После согласования README и push:

1. Добавить ключ NVD в Settings → Secrets and variables → Actions → New repository secret → `NVD_API_KEY`.
2. Открыть Actions → Security CI и дождаться успешного завершения обеих jobs.
3. Сохранить URL конкретного запуска вида `https://github.com/DeminGit/Information_Security_LAB1/actions/runs/<id>`.
4. Сделать скриншот общего Summary с зелёными jobs, веткой и commit SHA.
5. Открыть `tests-and-sast` → `Integration tests and SpotBugs + Find Security Bugs`.
   Снять экран с числом тестов, `BugInstance size is 0` и `BUILD SUCCESS`.
6. Скачать artifact `dependency-check`, открыть HTML-отчёт, снять экран с датой,
   числом проверенных зависимостей и результатом. Дополнительно снять успешный SCA step в Actions.
7. Положить реальные PNG в `docs/screenshots/` и добавить их относительными ссылками в README,
   вместе с URL успешного запуска. Не включать токены, `.env` и секреты в кадр.

Локальные отчёты: `target/surefire-reports/`, `target/spotbugsXml.xml`,
`target/dependency-check-report.html`, `target/dependency-check-report.json`.
Они генерируются сканерами; каталог `target` не хранится в Git.

При ошибке загрузки NVD нельзя утверждать, что уязвимостей нет:
нужно восстановить доступ и повторить SCA. Pipeline намеренно завершится ошибкой.
