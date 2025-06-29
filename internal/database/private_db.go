package database

import (
	"golang.org/x/crypto/bcrypt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// The private DB struct hold the database connection to the internal database behind the API. (Used for Projects, Users and other internal data)

type PrivateDB struct {
	DB *gorm.DB
}

type Users struct {
	ID       uint      `gorm:"primaryKey"`
	Username string    `gorm:"uniqueIndex"`
	Password string    `gorm:"not null"`
	Role     string    `gorm:"not null"` // e.g., "owner", "admin", "user"
	Projects []Project `gorm:"many2many:user_projects;"`
}

func (u *Users) BeforeCreate(tx *gorm.DB) (err error) {
	// Hash the password before storing it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *Users) CheckPassword(password string) bool {
	// Compare the provided password with the stored hashed password
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

type Project struct {
	ID           uint   `gorm:"primaryKey"`
	Name         string `gorm:"uniqueIndex"`
	Description  string `gorm:"not null"`
	OwnerID      uint   `gorm:"not null"`
	Owner        Users  `gorm:"foreignKey:OwnerID"`
	DatabaseURL  string `gorm:"not null"` // URL to the project's database
	DatabaseType string `gorm:"not null"` // e.g., "sqlite", "postgres", etc.
	Features     string `gorm:"not null"` // JSON or comma-separated list of features enabled for the project
}

func NewPrivateDB() (*PrivateDB, error) {
	db, err := gorm.Open(sqlite.Open("private.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate the schema
	err = db.AutoMigrate(&Users{}, &Project{})
	if err != nil {
		return nil, err
	}

	return &PrivateDB{DB: db}, nil
}

// Close closes the database connection
func (p *PrivateDB) Close() error {
	sqlDB, err := p.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetDB returns the underlying gorm.DB instance
func (p *PrivateDB) GetDB() *gorm.DB {
	return p.DB
}
