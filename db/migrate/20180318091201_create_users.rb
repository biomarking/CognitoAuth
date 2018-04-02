class CreateUsers < ActiveRecord::Migration[5.1]
  def change
    create_table :users do |t|
    	t.string :uuid
    	t.belongs_to :user_type, index:true
    	t.boolean :first_login, default: true
      	t.timestamps
    end
  end
end
