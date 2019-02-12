package kripto;

class LoggedInUser {

    private String userName, password;

    LoggedInUser(String userName, String password)
    {
        this.userName = userName;
        this.password = password;
    }


    String getUserName() {
        return userName;
    }

    String getPassword() {
        return password;
    }
}
