CREATE TABLE users (
  id                    bigserial,
  username              varchar(30) NOT NULL UNIQUE,
  password              varchar(80) NOT NULL,
  email                 varchar(50) UNIQUE,
  primary key (id)
);

CREATE TABLE roles (
  id                    serial,
  name                  varchar(50) not null,
  primary key (id)
);

CREATE TABLE users_roles (
  user_id               bigint not null,
  role_id               int not null,
  primary key (user_id, role_id),
  foreign key (user_id) references users (id),
  foreign key (role_id) references roles (id)
);

INSERT INTO roles (name)
values
('ROLE_USER'), ('ROLE_ADMIN');

INSERT INTO users (username, password, email)
values
('user', '$2a$04$Fx/SX9.BAvtPlMyIIqqFx.hLY2Xp8nnhpzvEEVINvVpwIPbA3v/.i', 'user@gmail.com'),
('admin', '$2a$04$Fx/SX9.BAvtPlMyIIqqFx.hLY2Xp8nnhpzvEEVINvVpwIPbA3v/.i', 'admin@gmail.com');

INSERT INTO users_roles (user_id, role_id)
VALUES
(1, 1),
(2, 2);