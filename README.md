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
