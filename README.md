# Задание: 
1. необходимо запустить локальный веб-сервер на Go (подойдет любой Http, Gin, Echo ) 
не использовать ORM, только чистый sql. использовать БД Sqlite, предварительно создав таблицы или вывести sql как миграцию при запуске веб-сервера. 

2. реализовать POST обработчик /user/register, который обрабатывает форму (PostForm) 
login (string)
password  (string)
name (string)
age (int)

(это не json)

эти значения необходимо сохранить в файловую БД 
пароль сохранить хэшем (bcrypt)

3. метод аутентификации /user/auth
в json:
login (string)
password  (string)

проверить логин и пароль, в случае успеха вернуть куки SESSTOKEN=<JWT TOKEN>
JWT токен обычный (HS256), с логином и user_id в полезной нагрузке

4. реализовать обработчик GET  /user/:name
(необходим middleware авторизации, который проверяет куки SESSTOKEN)

где по :name ищется в БД и возвращается в формате json результат:

{id: <id из БД>, "name": "имя", age: 25}

5. реализовать метод добавление номера, POST /user/phone (так же хранить в бд)
(необходим middleware авторизации, который проверяет куки SESSTOKEN)
в JSON 

phone - string (max: 12)
description - string (описание номера)
is_fax - bool (факс или нет)

добавляется за пользователем, в таблице должна быть колонка user_id
который будет браться из jwt

должна быть проверка на дубликат

6. реализовать метод получения номера GET /user/phone?q=<номер>
(необходим middleware авторизации, который проверяет куки SESSTOKEN)
ответ в JSON список тех, у кого есть этот номер

user_id, phone, description, is_fax

примечание: вводится может часть номера, поиск должен возвращать массив с подходящими номерами

7. реализовать метод PUT /user/phone для обновление данных номера
(необходим middleware авторизации, который проверяет куки SESSTOKEN)
поля 

phone_id
phone
is_fax
description

обновляются поля, user_id из jwt

8. реализовать метод DELETE для удаление номера /user/phone/<phone_id>
(необходим middleware авторизации, который проверяет куки SESSTOKEN)

приветствуется использование каких либо архитектур и комментирования кода 


**РЕШЕНИЕ**
1. Создание и проверка сервера
2. Создание POST запросов
3. 
 
