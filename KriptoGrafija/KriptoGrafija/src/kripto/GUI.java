package kripto;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static kripto.Encryption.*;

/**
 *
 * @author Peasant
 */
public class GUI extends Application{

    private static Scene mainScreen;
    private static KeyPairGenerator kpGen;
    static File hashedUserList = new File("C:\\Users\\Besitzer\\IdeaProjects\\KriptoGrafija\\out\\production\\KriptoGrafija\\kripto\\hashedUserList.txt");
    static CertificateAuthority certificateAuthority;

    @Override
    public void start(Stage primaryStage)
    {
        Thread threadCA=new Thread(()-> {
            certificateAuthority = new CertificateAuthority(new BouncyCastleProvider());
        });
        threadCA.start();

        Thread threadKeyGen = new Thread (() -> {
            try {
                kpGen = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        });
        threadKeyGen.start();

        Label lb1=new Label("Username:");
        lb1.setStyle("-fx-text-fill: #ffffff");
        HBox lb1Hbox = new HBox(lb1);
        lb1Hbox.setAlignment(Pos.CENTER_LEFT);

        Label lb2 = new Label("Password:");
        lb2.setStyle("-fx-text-fill: #ffffff");
        HBox lb2Hbox = new HBox(lb2);
        lb2Hbox.setAlignment(Pos.CENTER_LEFT);

        TextField textUser=new TextField();
        PasswordField textPassword= new PasswordField();

        Label lb3=new Label();
        lb3.setStyle("-fx-text-fill: #ffffff");
        HBox lb3Hbox = new HBox(lb3);
        lb3Hbox.setAlignment(Pos.CENTER_LEFT);

        ChoiceBox<String> choiceBox = new ChoiceBox();
        choiceBox.getItems().add("Encrypt");
        choiceBox.getItems().add("Decrypt");
        choiceBox.setValue("Encrypt");

        Button loginConfirm = new Button("Confirm");
        loginConfirm.setOnAction(Event ->{
            if(!login(textUser.getText(), textPassword.getText(), primaryStage, choiceBox.getValue()))
                lb3.setText("Wrong username or password");
        });


        Button registerUserButton = new Button("Register new user");
        registerUserButton.setOnAction((ActionEvent Event) -> {
            setRegisterScene(primaryStage);
        });

        VBox vbox=new VBox(20);
        vbox.getChildren().addAll(lb1Hbox,textUser,lb2Hbox,textPassword,choiceBox,loginConfirm,registerUserButton,lb3Hbox);
        vbox.setAlignment(Pos.TOP_CENTER);
        vbox.setPadding(new Insets(50, 150, 0, 150));

        BorderPane layout=new BorderPane();
        layout.setCenter(vbox);
        layout.setStyle("-fx-background-color: #000030");

        Scene scene=new Scene(layout,720,480);
        mainScreen = scene;
        primaryStage.setScene(scene);
        primaryStage.setTitle("CODE CRYPT");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }

    private boolean login(String userName, String password, Stage primaryStage, String modeSelected)
    {
        try (   FileReader userListFile = new FileReader(hashedUserList);
                BufferedReader userList = new BufferedReader(userListFile)
        )
        {
            String typedUsername = getStringHashHexadecimal(userName,"SHA-256");
            String typedPassword = getStringHashHexadecimal(password,"SHA-256");
            String readUserName,readPassword;
            while(userList.readLine() != null)
            {
                readUserName = userList.readLine();
                readPassword = userList.readLine();

                readUserName = readUserName.replace("user:", "");
                readPassword = readPassword.replace("password:", "");
                if((typedUsername.equals(readUserName)) && (typedPassword.equals(readPassword)))
                {
                    while(certificateAuthority == null)
                        Thread.sleep(250);

                    X509Certificate userCertificate = certificateAuthority.retrieveCertificate(userName);

                    if(CertificateAuthority.isValidCertificate(userCertificate)) {
                        setLoggedInScene(primaryStage, modeSelected, new LoggedInUser(userName, password));
                        return true;
                    }
                    certificateAuthority.writeCRL(certificateAuthority.generateCRList(certificateAuthority.caCert,certificateAuthority.caKeyPair.getPrivate(),userCertificate));
                    Alert alert = new Alert(Alert.AlertType.WARNING, "Certificate no longer valid!" + " !", ButtonType.OK);
                    alert.showAndWait();
                    return false;
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private void setLoggedInScene(Stage primaryStage, String modeSelected, LoggedInUser loggedInUser)
    {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().addAll(
                new ExtensionFilter("Java Files", "*.java"),
                new ExtensionFilter("Text Files","*.txt"));

        Label fileLabel = new Label("Please choose your file");
        fileLabel.setStyle("-fx-text-fill: #ffffff");

        ChoiceBox<String> algorithmChoice = new ChoiceBox();
        algorithmChoice.getItems().add("AES-192");
        algorithmChoice.getItems().add("AES-256");
        algorithmChoice.getItems().add("DESede");
        algorithmChoice.getItems().add("DES");
        algorithmChoice.setValue("DES");

        ChoiceBox<String> hashChoice = new ChoiceBox();
        hashChoice.getItems().add("SHA-256");
        hashChoice.getItems().add("SHA-512");
        hashChoice.getItems().add("MD5");
        hashChoice.setValue("MD5");

        Button fileChoosingButton = new Button("Choose your file");
        fileChoosingButton.setOnAction((ActionEvent event) ->
        {
            File chosenFile = fileChooser.showOpenDialog(primaryStage);
            if(chosenFile == null)
                fileLabel.setText("Please select a file");
            else
                fileLabel.setText(chosenFile.getAbsolutePath());
        });

        VBox vBox = new VBox(20);
        vBox.getChildren().addAll(fileLabel,fileChoosingButton);
        vBox.setAlignment(Pos.TOP_CENTER);
        vBox.setPadding(new Insets(150, 0, 0, 0));

        if(modeSelected.equals("Encrypt"))
        {
            Label recipientInfo = new Label("Encrypted file recipient:");
            recipientInfo.setStyle("-fx-text-fill: #ffffff");

            HBox lb1Hbox = new HBox(recipientInfo);
            lb1Hbox.setAlignment(Pos.CENTER);

            TextField recipient = new TextField();
            HBox recipientHbox = new HBox(recipient);
            recipientHbox.setAlignment(Pos.CENTER);

            Button encryptionButton = new Button("Start encryption");
            vBox.getChildren().addAll(lb1Hbox, recipientHbox,algorithmChoice,hashChoice,encryptionButton);

            encryptionButton.setOnAction(e->{
                if(!fileLabel.getText().equals("Please choose your file")) {
                    codeEncryption(loggedInUser, recipient.getText(), algorithmChoice.getValue(), hashChoice.getValue(), new File(fileLabel.getText()));
                }
            });
        }

        else if(modeSelected.equals("Decrypt"))
        {
            Button decryptionButton = new Button("Start Decryption");
            vBox.getChildren().addAll(decryptionButton);
            decryptionButton.setOnAction(e -> {
                if(!fileLabel.getText().equals("Please choose your file"))
                    codeDecryption(loggedInUser,new File(fileLabel.getText()));
            });
        }

        BorderPane layout=new BorderPane();
        layout.setCenter(vBox);
        layout.setStyle("-fx-background-color: #000030");

        Scene scene=new Scene(layout,720,720);
        primaryStage.setScene(scene);
        primaryStage.setTitle("CODE CRYPT");
        primaryStage.show();
    }

    private void setRegisterScene(Stage primaryStage)
    {
        Label lb1=new Label("Enter your username:");
        lb1.setStyle("-fx-text-fill: #ffffff");
        HBox lb1Hbox = new HBox(lb1);
        lb1Hbox.setAlignment(Pos.CENTER_LEFT);

        TextField userName = new TextField();

        Label lb2 = new Label("Password:");
        lb2.setStyle("-fx-text-fill: #ffffff");
        HBox lb2Hbox = new HBox(lb2);
        lb2Hbox.setAlignment(Pos.CENTER_LEFT);

        PasswordField password = new PasswordField();

        Label lb3 = new Label("Password confirm:");
        lb3.setStyle("-fx-text-fill: #ffffff");
        HBox lb3Hbox = new HBox(lb3);
        lb2Hbox.setAlignment(Pos.CENTER_LEFT);

        PasswordField passwordConfirm = new PasswordField();

        Button registrationConfirm = new Button("Confirm Entry");
        registrationConfirm.setOnAction(Event -> {
            if(!userName.getText().equals(""))
                if(password.getText().equals(passwordConfirm.getText()))
                {
                    if(!registerUser(userName.getText(), passwordConfirm.getText()))
                    {
                        Alert boxAlert = new Alert(Alert.AlertType.ERROR, "User is already registered");
                        boxAlert.setTitle("Register");
                        boxAlert.setHeaderText("Username already registered");
                        boxAlert.setResizable(false);
                        boxAlert.setContentText("Press OK to try again.");
                        boxAlert.showAndWait();
                    }
                    else
                    {
                        Alert boxAlert = new Alert(Alert.AlertType.INFORMATION, "Successeful registration");
                        boxAlert.setTitle("Register");
                        boxAlert.setHeaderText("Registration successful,you will be sent back to the login screen.");
                        boxAlert.setResizable(false);
                        boxAlert.setContentText("Press OK button to continue.");
                        boxAlert.showAndWait();
                        primaryStage.setScene(mainScreen);
                        primaryStage.show();
                    }
                }
                else
                {
                    Alert boxAlert = new Alert(Alert.AlertType.ERROR, "Password and password confirmation do not match");
                    boxAlert.setTitle("Register");
                    boxAlert.setHeaderText("Password and password confirmation do not match");
                    boxAlert.setResizable(false);
                    boxAlert.setContentText("Press OK to try again.");
                    boxAlert.showAndWait();
                }
            else
            {
                Alert boxAlert = new Alert(Alert.AlertType.ERROR,"Enter a username");
                boxAlert.showAndWait();
            }
        });

        VBox vbox = new VBox(20);
        vbox.getChildren().addAll(lb1Hbox,userName,lb2Hbox,password,lb3Hbox,passwordConfirm,registrationConfirm);
        vbox.setAlignment(Pos.TOP_CENTER);
        vbox.setPadding(new Insets(25, 150, 0, 150));

        BorderPane layout=new BorderPane();
        layout.setCenter(vbox);
        layout.setStyle("-fx-background-color: #000030");

        Scene scene=new Scene(layout,720,480);
        primaryStage.setScene(scene);
        primaryStage.setTitle("CODE CRYPT");
        primaryStage.show();
    }

    private static boolean registerUser(String userName, String password)
    {
        if(userIsRegistered(userName))
            return false;
        try (   FileWriter fW = new FileWriter(hashedUserList, true);
                PrintWriter userListFile = new PrintWriter(fW))
        {
            userListFile.println("---------------------------------------");
            userListFile.println("user:" + Encryption.getStringHashHexadecimal(userName,"SHA-256"));
            userListFile.println("password:" + Encryption.getStringHashHexadecimal(password,"SHA-256"));

            while(kpGen == null) {
                Thread.sleep(250);
            }
            while (certificateAuthority == null) {
                Thread.sleep(250);
            }

            KeyPair newUserKeyPair = kpGen.genKeyPair();

            X509Certificate newUserCertificate = certificateAuthority.createSignedUserCertificate("C=" + userName + ",O=ETF",newUserKeyPair.getPublic());
            Encryption.writeKey(userName, password, newUserKeyPair);

            File certificateFolder = new File(GUI.hashedUserList.getParent() + File.separatorChar + userName + "Certificate");
            certificateFolder.mkdir();

            try (FileOutputStream certWriter = new FileOutputStream(new File(certificateFolder.getAbsolutePath() + File.separatorChar + userName + ".cer"))) {
                certWriter.write(newUserCertificate.getEncoded());
                certWriter.flush();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return true;

        } catch (OperatorCreationException | CertificateException | IOException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }


        static boolean userIsRegistered(String username)
    {
        try(    FileReader fr= new FileReader(hashedUserList);
                BufferedReader fileReader = new BufferedReader(fr))
        {
            String hashedUsername = Encryption.getStringHashHexadecimal(username,"SHA-256");
            for(String lineRead=fileReader.readLine(); lineRead!=null; lineRead=fileReader.readLine())
                if(lineRead.contains(hashedUsername))
                    return true;

        } catch (IOException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }


}