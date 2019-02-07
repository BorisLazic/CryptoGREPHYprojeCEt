package kripto;

public class LoggedInUser {

    private String userName, password;

    LoggedInUser(String userName, String password)
    {
        this.userName = userName;
        this.password = password;
    }


    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }
}
