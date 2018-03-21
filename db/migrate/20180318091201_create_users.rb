class CreateUsers < ActiveRecord::Migration[5.1]
  def change
    create_table :users do |t|
    	t.string :email_address
    	t.string :auth_provider
    	t.belongs_to :user_type, index:true
      	t.timestamps
    end
  end
end
