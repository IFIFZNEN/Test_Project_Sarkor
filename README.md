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
     УСПЕШНЫЙ ЗАПУСК СЕРВЕРА: ![image](https://github.com/IFIFZNEN/Test_Project_Sarkor/assets/104571864/31d99c45-c22e-48d1-a014-b4cd8c55b854)
   
     ОТОБРАЖЕНИЕ РАБОТЫ ПРОГРАММЫ В БРАУЗЕРЕ ПО ССЫЛКЕ: http://localhost:8080/ :

   ![image](https://github.com/IFIFZNEN/Test_Project_Sarkor/assets/104571864/14fe1874-1ea3-4d1d-b62f-e346eb8f8fbc)

3. Создание POST запросов:

     ПРИМЕР РАБОТЫ ОТПРАВКИ ЗАПРОСА НА СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ:
   
     ![image](https://github.com/IFIFZNEN/Test_Project_Sarkor/assets/104571864/1ecf11a4-f41a-43d5-98fc-7cead8c18970)

     ПРИМЕР РАБОТЫ ФУНЦИИ ДЛЯ АВТОРИЗАЦИИ ПОЛЬЗОВАТЕЛЯ:
   
     ![image](https://github.com/IFIFZNEN/Test_Project_Sarkor/assets/104571864/c24d6ad2-d557-432a-b592-f624b905f8c1)

     ПРИМЕР РАБОТЫ ФУНКЦИИ ПО ВЫВОДУ ИНФОРМАЦИИ ВИДЕ JSON:
   
     ![image](https://github.com/IFIFZNEN/Test_Project_Sarkor/assets/104571864/167bbd55-d361-4cf1-ac61-e96d6ee8913d)


5. 
6. 
 
