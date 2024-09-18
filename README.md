<<<<<<< HEAD
# Sports-Federation-Management-System

**Sports Federation Management System** is a comprehensive platform designed to streamline the management of sports federations. It provides tools for managing athletes, competitions, referee assignments, and transfer processes. The system aims to simplify operations and enhance transparency within the federation's activities.

## Features

- **User Role Management**: Manage different user roles such as administrators, club representatives, coaches, and referees.
- **Athlete Management**: Track athlete information, participation history, and club-to-club transfers.
- **Competition Management**: Manage the addition and participation of athletes, coaches, and referees in competitions.
- **Results Management**: Process competition results categorized by age groups and sports disciplines.
- **Referee Assignment**: Facilitate referee requests for competitions and manage the assignment process.
- **Secure Login System**: Ensure secure authentication for all users, including password reset functionality.
- **User Activity Log**: Track user activity, including page visits and access history.

## Technologies Used

- **Python**: The primary programming language for the project.
- **Flask**: The web framework used to build the application.
- **Flask-SQLAlchemy**: ORM (Object Relational Mapper) used for database management.
- **SQLite**: The default database, with the option to switch to PostgreSQL or MySQL.
- **Pytz**: Library used for time zone support.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/mefaay/federation-management-system.git
    ```

2. Navigate to the project directory:

    ```bash
    cd federation-management-system
    ```

3. Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # For Windows: venv\Scripts\activate
    ```

4. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

5. Set up the database:

    ```bash
    python setup_database.py
    ```

6. Run the application:

    ```bash
    python app.py
    ```

7. Open your browser and navigate to:

    ```text
    http://127.0.0.1:5000
    ```

## Usage

- **Admin Users** can manage athletes, competitions, and referees.
- **Club Representatives** can handle athlete transfers and participation requests.
- **Coaches** can add athletes to competitions.
- **Referees** can request to officiate competitions and track their assignments.

## Contribution

We welcome contributions to the project! Feel free to open an issue or submit a pull request to suggest improvements or report bugs.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
=======
<<<<<<< HEAD
# Sports-Federation-Management-System
Sports Federation Management System is a comprehensive platform designed to streamline the management of sports federations. It provides tools for managing athletes, competitions, referee assignments, and transfer processes. The system aims to simplify operations and enhance transparency within the federation's activities
=======
# Federasyon Yönetim Sistemi

Bu proje, sporcular, hakemler, müsabakalar ve sonuçlarının yönetimini sağlayan bir **Federasyon Yönetim Sistemi**'dir. Kullanıcı rolleri yönetimi, sporcu transfer takibi ve müsabaka sonuçlarının işlenmesi gibi çeşitli özellikler içerir.

## Özellikler

- **Kullanıcı Rolleri Yönetimi**: Yöneticiler, kulüp temsilcileri, antrenörler ve hakemler gibi farklı kullanıcı rollerini yönetme.
- **Sporcu Yönetimi**: Sporcu bilgilerini, katılım geçmişini ve kulüpler arası transferlerini izleme.
- **Müsabaka Yönetimi**: Müsabakalara katılacak sporcu, antrenör ve hakemlerin eklenmesi ve yönetimi.
- **Sonuç Yönetimi**: Müsabaka sonuçlarını, yaş kategorilerine ve spor dallarına göre işleme.
- **Hakem Atama**: Hakemlerin müsabakalar için talepte bulunması ve atama sürecinin yönetimi.
- **Güvenli Giriş Sistemi**: Tüm kullanıcılar için güvenli kimlik doğrulama ve şifre sıfırlama işlevi.
- **Kullanıcı Aktivitesi Kaydı**: Kullanıcıların ziyaret ettikleri sayfalar ve erişim geçmişi kaydı.

## Kullanılan Teknolojiler

- **Python**: Projenin temel programlama dili.
- **Flask**: Web uygulamasının temelini oluşturan web çatısı.
- **Flask-SQLAlchemy**: Veritabanı yönetimi için kullanılan ORM (Object Relational Mapper).
- **SQLite**: Varsayılan veritabanı, PostgreSQL veya MySQL ile değiştirilebilir.
- **Pytz**: Zaman dilimi desteği için kullanılan kütüphane.

## Kurulum Adımları

1. **Depoyu klonlayın:**
   ```bash
   git clone https://github.com/mefaay/federation-management-system.git
>>>>>>> bfed078 (Updated README.md with project description)
>>>>>>> 4a74052ffbef38595a6e09d707e3425893edb5f7
