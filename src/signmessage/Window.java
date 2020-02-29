package signmessage;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import java.awt.Font;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.awt.event.ActionEvent;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

public class Window {

	private JFrame frame;
	private JTextField textFieldPub;
	private JTextField textFieldPriv;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Window window = new Window();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public Window() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame("Sign Messages");
		frame.setResizable(false);
		frame.setBounds(100, 100, 510, 600);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		
		JLabel lblPublicKey = new JLabel("Public Key:");
		lblPublicKey.setFont(new Font("Arial", Font.PLAIN, 12));
		lblPublicKey.setBounds(10, 11, 79, 14);
		frame.getContentPane().add(lblPublicKey);
		
		textFieldPub = new JTextField();
		textFieldPub.setText("FileName");
		textFieldPub.setFont(new Font("Arial", Font.PLAIN, 12));
		textFieldPub.setBounds(10, 35, 155, 20);
		frame.getContentPane().add(textFieldPub);
		textFieldPub.setColumns(10);
		
		textFieldPriv = new JTextField();
		textFieldPriv.setText("FileName");
		textFieldPriv.setFont(new Font("Arial", Font.PLAIN, 12));
		textFieldPriv.setColumns(10);
		textFieldPriv.setBounds(175, 35, 155, 20);
		frame.getContentPane().add(textFieldPriv);
		
		JLabel lblPrivateKey = new JLabel("Private Key:");
		lblPrivateKey.setFont(new Font("Arial", Font.PLAIN, 12));
		lblPrivateKey.setBounds(175, 11, 91, 14);
		frame.getContentPane().add(lblPrivateKey);
		
		JButton btnGenerateRsaKey = new JButton("Generate RSA Key");
		btnGenerateRsaKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String fileNamePub = textFieldPub.getText();
				String fileNamePriv = textFieldPriv.getText();
				
				KeyPair pair = null;
				try {
					pair = SHA256.generateKeyPair(2048);
					PrivateKey priv = pair.getPrivate();
					PublicKey pub = pair.getPublic();
					SHA256.storePublicKey(pub, fileNamePub);
					SHA256.storePrivateKey(priv, fileNamePriv);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				
			}
		});
		btnGenerateRsaKey.setFont(new Font("Arial", Font.PLAIN, 12));
		btnGenerateRsaKey.setBounds(340, 34, 140, 23);
		frame.getContentPane().add(btnGenerateRsaKey);
		
		JTextArea textAreaMessage = new JTextArea();
		textAreaMessage.setBounds(10, 91, 470, 200);
		textAreaMessage.setLineWrap(true);
		frame.getContentPane().add(textAreaMessage);
		
		JLabel lblMessage = new JLabel("Message:");
		lblMessage.setFont(new Font("Arial", Font.PLAIN, 12));
		lblMessage.setBounds(10, 66, 121, 14);
		frame.getContentPane().add(lblMessage);
		
		JLabel lblSignature = new JLabel("Signature:");
		lblSignature.setFont(new Font("Arial", Font.PLAIN, 12));
		lblSignature.setBounds(10, 302, 79, 14);
		frame.getContentPane().add(lblSignature);
		
		JTextArea textAreaSignature = new JTextArea();
		textAreaSignature.setBounds(10, 327, 470, 140);
		textAreaSignature.setLineWrap(true);
		frame.getContentPane().add(textAreaSignature);
		
		JLabel labelVerify = new JLabel("");
		labelVerify.setHorizontalAlignment(SwingConstants.CENTER);
		labelVerify.setFont(new Font("Arial Black", Font.PLAIN, 12));
		labelVerify.setBounds(10, 512, 470, 20);
		frame.getContentPane().add(labelVerify);
		
		JButton btnSignMessage = new JButton("Sign Message");
		btnSignMessage.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String message = textAreaMessage.getText();
				String fileName = textFieldPriv.getText();
				PrivateKey priv;
				String signature = null;
				try {
					priv = SHA256.getPrivateKey(fileName);
					signature = SHA256.Sign(message, priv);
				}
				catch (Exception e1) {
					e1.printStackTrace();
				}
				textAreaSignature.setText(signature);
				
			}
		});
		btnSignMessage.setFont(new Font("Arial", Font.PLAIN, 12));
		btnSignMessage.setBounds(10, 478, 230, 23);
		frame.getContentPane().add(btnSignMessage);
		
		JButton btnVerifiySignature = new JButton("Verify Signature");
		btnVerifiySignature.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String message = textAreaMessage.getText();
				String signature = textAreaSignature.getText();
				String fileName = textFieldPub.getText();
				PublicKey publickey;
				try {
					publickey = SHA256.getPublicKey(fileName);
					boolean correctSignature = SHA256.verify(message, signature, publickey);
					if (correctSignature == true) {
						labelVerify.setText("Signature is Valid!");
					}
					else {
						labelVerify.setText("Invalid Signature");
					}
				} 
				catch (Exception e1) {
					e1.printStackTrace();
				}
				
			}
		});
		btnVerifiySignature.setFont(new Font("Arial", Font.PLAIN, 12));
		btnVerifiySignature.setBounds(250, 478, 230, 23);
		frame.getContentPane().add(btnVerifiySignature);
		
	}
}
